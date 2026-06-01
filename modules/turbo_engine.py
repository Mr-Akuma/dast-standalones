"""
TurboEngine — Turbo Intruder-style HTTP attack engine for the DAST platform.

Supports:
  - Sniper mode: iterate a wordlist across a thread pool with persistent sessions
  - Race condition mode: N threads fire simultaneously via threading.Barrier
  - %s payload injection with automatic Content-Length fixing
  - SSE-compatible result streaming
"""
from __future__ import annotations

import queue
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Generator, List, Optional
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class IntruderResult:
    req_id:           int
    payload:          str
    status:           int
    length:           int
    wordcount:        int
    time_ms:          float
    arrival_ms:       float
    interesting:      bool
    request_raw:      str
    response_headers: str
    response_body:    str
    error:            str = ""
    conn_id:          int = 0

    def to_dict(self) -> dict:
        return {
            "req_id":           self.req_id,
            "payload":          self.payload,
            "status":           self.status,
            "length":           self.length,
            "wordcount":        self.wordcount,
            "time_ms":          self.time_ms,
            "arrival_ms":       self.arrival_ms,
            "interesting":      self.interesting,
            "request_raw":      self.request_raw,
            "response_headers": self.response_headers,
            "response_body":    self.response_body[:20000],
            "error":            self.error,
            "conn_id":          self.conn_id,
        }


# ── Template helpers ──────────────────────────────────────────────────────────

def _apply_payload(template: str, payload: str) -> str:
    """Replace first %s occurrence with the payload (literal, not format-string)."""
    return template.replace("%s", payload, 1)


def _fix_content_length(raw_request: str) -> str:
    """Recalculate Content-Length if the header is present."""
    if "\r\n\r\n" in raw_request:
        head, body = raw_request.split("\r\n\r\n", 1)
    elif "\n\n" in raw_request:
        head, body = raw_request.split("\n\n", 1)
        raw_request = raw_request.replace("\n", "\r\n")
        head = head.replace("\r\r\n", "\r\n")
    else:
        return raw_request

    if "content-length" not in head.lower():
        return raw_request

    body_bytes = len(body.encode("utf-8", errors="replace"))
    head = re.sub(
        r"(?i)(Content-Length\s*:\s*)\d+",
        lambda m: m.group(1) + str(body_bytes),
        head,
    )
    return head + "\r\n\r\n" + body


def _parse_raw_request(raw: str) -> dict:
    """Parse a raw HTTP request string into components."""
    raw = raw.replace("\r\n", "\n")
    lines = raw.split("\n")
    if not lines:
        return {"method": "GET", "path": "/", "headers": {}, "body": None}

    req_line = lines[0].strip().split(" ", 2)
    method = req_line[0] if req_line else "GET"
    path   = req_line[1] if len(req_line) > 1 else "/"

    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line == "":
                in_body = True
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip() or None
    return {"method": method, "path": path, "headers": headers, "body": body}


# ── Engine ────────────────────────────────────────────────────────────────────

class TurboEngine:
    """
    Core Turbo Intruder-style engine.

    Usage (sniper):
        engine = TurboEngine(endpoint, template, payloads, threads=10)
        engine.start()
        for result in engine.stream_results():
            if result is None: break
            process(result)

    Usage (race):
        engine = TurboEngine(endpoint, template, [], race_mode=True, race_count=20)
        engine.start()
        for result in engine.stream_results():
            ...
    """

    def __init__(
        self,
        endpoint: str,
        template: str,
        payloads: List[str],
        threads: int = 5,
        requests_per_connection: int = 50,
        timeout: int = 10,
        max_retries: int = 2,
        race_mode: bool = False,
        race_count: int = 20,
        delay_ms: float = 0.0,
        fix_content_length: bool = True,
    ):
        parsed = urlparse(endpoint)
        self._scheme  = parsed.scheme or "https"
        self._host    = parsed.hostname or ""
        self._port    = parsed.port or (443 if self._scheme == "https" else 80)
        self._base    = f"{self._scheme}://{self._host}:{self._port}"

        self._template  = template
        self._payloads  = payloads
        self._threads   = max(1, threads)
        self._rpc       = max(1, requests_per_connection)
        self._timeout   = timeout
        self._retries   = max_retries
        self._race_mode = race_mode
        self._race_count = max(2, race_count)
        self._delay_s   = delay_ms / 1000.0
        self._fix_cl    = fix_content_length

        self._work_q:   queue.Queue = queue.Queue(maxsize=500)
        self._result_q: queue.Queue = queue.Queue()
        self._stop      = threading.Event()
        self._done      = threading.Event()
        self._workers:  list[threading.Thread] = []

        self._start_ns: int = 0
        self._req_id    = 0
        self._id_lock   = threading.Lock()
        self._conn_id   = 0
        self._conn_lock = threading.Lock()

        self._success   = 0
        self._errors    = 0
        self._stats_lock = threading.Lock()

    # ── public API ─────────────────────────────────────────────────────────────

    def start(self):
        self._start_ns = time.monotonic_ns()
        self._start_t  = time.monotonic()
        if self._race_mode:
            self._launch_race()
        else:
            self._launch_sniper()

    def stop(self):
        self._stop.set()

    def stream_results(self) -> Generator[Optional[IntruderResult], None, None]:
        """Yield IntruderResult objects as they arrive; yields None when done."""
        while True:
            if self._stop.is_set() and self._result_q.empty():
                return
            try:
                item = self._result_q.get(timeout=0.4)
                if item is None:
                    return
                yield item
            except queue.Empty:
                if self._done.is_set() and self._result_q.empty():
                    return

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            elapsed = time.monotonic() - getattr(self, "_start_t", time.monotonic())
            rps = self._success / elapsed if elapsed > 0 else 0
            return {
                "success": self._success,
                "errors":  self._errors,
                "queued":  self._work_q.qsize(),
                "elapsed_s": round(elapsed, 1),
                "rps":     round(rps, 1),
                "stopped": self._stop.is_set(),
                "done":    self._done.is_set(),
            }

    # ── internals ──────────────────────────────────────────────────────────────

    def _next_id(self) -> int:
        with self._id_lock:
            self._req_id += 1
            return self._req_id

    def _next_conn(self) -> int:
        with self._conn_lock:
            self._conn_id += 1
            return self._conn_id

    def _arrival_ms(self) -> float:
        return (time.monotonic_ns() - self._start_ns) / 1_000_000

    def _send(self, session: requests.Session, raw: str, payload: str,
              req_id: int, conn_id: int) -> IntruderResult:
        """Execute one HTTP request and return a result object."""
        if self._fix_cl:
            raw = _fix_content_length(raw)

        parsed = _parse_raw_request(raw)
        method  = parsed["method"]
        path    = parsed["path"]
        headers = parsed["headers"]
        body    = parsed["body"]

        url = self._base + path
        arrival = self._arrival_ms()
        t0 = time.monotonic()

        try:
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode("utf-8", errors="replace") if body else None,
                timeout=self._timeout,
                verify=False,
                allow_redirects=False,
            )
            elapsed = (time.monotonic() - t0) * 1000

            try:
                body_text = resp.text
            except Exception:
                body_text = resp.content.decode("latin-1", errors="replace")

            resp_headers = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            resp_status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}"

            with self._stats_lock:
                self._success += 1

            return IntruderResult(
                req_id=req_id,
                payload=payload,
                status=resp.status_code,
                length=len(resp.content),
                wordcount=len(body_text.split()),
                time_ms=round(elapsed, 1),
                arrival_ms=round(arrival, 1),
                interesting=False,
                request_raw=raw,
                response_headers=resp_status_line + "\r\n" + resp_headers,
                response_body=body_text,
                conn_id=conn_id,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            with self._stats_lock:
                self._errors += 1
            return IntruderResult(
                req_id=req_id,
                payload=payload,
                status=0,
                length=0,
                wordcount=0,
                time_ms=round(elapsed, 1),
                arrival_ms=round(arrival, 1),
                interesting=False,
                request_raw=raw,
                response_headers="",
                response_body="",
                error=str(exc),
                conn_id=conn_id,
            )

    # ── sniper mode ────────────────────────────────────────────────────────────

    def _worker(self, worker_id: int):
        conn_id  = self._next_conn()
        session  = self._new_session()
        req_count = 0

        while not self._stop.is_set():
            try:
                item = self._work_q.get(timeout=0.5)
            except queue.Empty:
                if self._done.is_set():
                    break
                continue

            if item is None:
                self._work_q.task_done()
                break

            req_id, raw, payload = item
            result = self._send(session, raw, payload, req_id, conn_id)
            self._result_q.put(result)
            self._work_q.task_done()
            req_count += 1

            if req_count >= self._rpc:
                session.close()
                session   = self._new_session()
                conn_id   = self._next_conn()
                req_count = 0

            if self._delay_s > 0:
                time.sleep(self._delay_s)

        session.close()

    def _new_session(self) -> requests.Session:
        s = requests.Session()
        s.verify = False
        s.headers["Connection"] = "keep-alive"
        return s

    def _launch_sniper(self):
        for i in range(self._threads):
            t = threading.Thread(
                target=self._worker,
                args=(i,),
                daemon=True,
                name=f"turbo-w{i}",
            )
            t.start()
            self._workers.append(t)

        def _feeder():
            for payload in self._payloads:
                if self._stop.is_set():
                    break
                raw    = _apply_payload(self._template, payload)
                req_id = self._next_id()
                while not self._stop.is_set():
                    try:
                        self._work_q.put((req_id, raw, payload), timeout=0.5)
                        break
                    except queue.Full:
                        continue

            # Signal workers to stop
            self._done.set()
            for _ in self._workers:
                try:
                    self._work_q.put(None, timeout=2)
                except queue.Full:
                    pass

            for w in self._workers:
                w.join(timeout=self._timeout + 5)

            self._result_q.put(None)  # Done sentinel

        threading.Thread(target=_feeder, daemon=True, name="turbo-feed").start()

    # ── race condition mode ─────────────────────────────────────────────────────

    def _race_worker(self, barrier: threading.Barrier, raw: str, payload: str,
                     req_id: int, conn_id: int):
        session = self._new_session()
        try:
            barrier.wait()  # All threads arrive → all proceed simultaneously
            result = self._send(session, raw, payload, req_id, conn_id)
            self._result_q.put(result)
        except threading.BrokenBarrierError:
            pass
        finally:
            session.close()

    def _launch_race(self):
        n       = self._race_count
        payload = self._payloads[0] if self._payloads else ""
        raw     = _apply_payload(self._template, payload)
        barrier = threading.Barrier(n)
        threads = []

        for i in range(n):
            req_id  = self._next_id()
            conn_id = self._next_conn()
            t = threading.Thread(
                target=self._race_worker,
                args=(barrier, raw, payload, req_id, conn_id),
                daemon=True,
                name=f"race-{i}",
            )
            t.start()
            threads.append(t)

        def _waiter():
            for t in threads:
                t.join(timeout=self._timeout + 10)
            self._done.set()
            self._result_q.put(None)

        threading.Thread(target=_waiter, daemon=True, name="race-waiter").start()
