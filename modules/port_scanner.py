"""
Port Scanner — TCP service discovery alongside web application scanning.
Equivalent to ZAP's Port Scanner add-on.

Uses asyncio for concurrent port probing with configurable timeout.
Identifies high-risk open ports and grabs service banners.
"""
from __future__ import annotations
import asyncio
import socket
import time
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class PortResult:
    host: str
    port: int
    state: str
    service_guess: str
    banner: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PortFinding:
    host: str
    port: int
    service: str
    finding: str
    severity: str
    evidence: str
    cwe: str
    agent_id: str = "port_scanner"
    icon: str = "\U0001f50c"

    def to_dict(self) -> dict:
        return asdict(self)


TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017, 5432, 6379, 6380,
    11211, 9300, 2181, 5601, 4848, 8161, 61616, 4672, 2375, 2376, 5000, 7001,
    9090, 4444, 1099, 7002, 8161, 9999, 8000, 8001, 9000, 9001, 9002, 4567,
    5984, 7474, 7473, 9042, 9160, 8983, 9200, 15672, 5672, 5671, 1883, 8883,
    5044, 9600, 7777, 8088, 8089, 8090, 5000, 6000, 7000, 9100, 3000, 3001,
    4000, 4001, 5500, 8008, 8181, 8282, 8383, 8484, 8585, 8686, 8787, 9080,
    9443, 9800, 9898, 10000, 10001, 10080,
]

_RISKY_PORTS = {
    21: ("FTP", "High", "FTP service exposed — credentials sent in cleartext"),
    22: ("SSH", "Info", "SSH service — check for key auth and version"),
    23: ("Telnet", "Critical", "Telnet exposed — unencrypted remote access"),
    25: ("SMTP", "Medium", "SMTP relay may be open"),
    3306: ("MySQL", "High", "MySQL database port exposed directly"),
    5432: ("PostgreSQL", "High", "PostgreSQL database port exposed directly"),
    6379: ("Redis", "Critical", "Redis port exposed — often unauthenticated"),
    27017: ("MongoDB", "Critical", "MongoDB port exposed — often unauthenticated"),
    9200: ("Elasticsearch", "Critical", "Elasticsearch port exposed — often unauthenticated"),
    9300: ("Elasticsearch Transport", "High", "Elasticsearch transport exposed"),
    11211: ("Memcached", "High", "Memcached exposed — DDoS amplification risk"),
    2375: ("Docker API (HTTP)", "Critical", "Docker daemon exposed without TLS"),
    2376: ("Docker API (TLS)", "Medium", "Docker daemon exposed with TLS — check auth"),
    5900: ("VNC", "High", "VNC remote desktop exposed"),
    3389: ("RDP", "High", "RDP Windows Remote Desktop exposed"),
    8161: ("ActiveMQ Console", "High", "ActiveMQ web console exposed"),
    7001: ("WebLogic", "High", "WebLogic admin port exposed"),
    4848: ("GlassFish Admin", "High", "GlassFish admin console exposed"),
    1099: ("Java RMI", "High", "Java RMI registry exposed"),
    5984: ("CouchDB", "High", "CouchDB exposed — check authentication"),
    7474: ("Neo4j HTTP", "High", "Neo4j database HTTP exposed"),
    15672: ("RabbitMQ Management", "Medium", "RabbitMQ management console exposed"),
    5672: ("AMQP", "Medium", "AMQP message broker exposed"),
    1883: ("MQTT", "Medium", "MQTT broker exposed — IoT protocol"),
}


class PortScanner:
    """Async TCP port scanner with banner grabbing and risk classification."""

    def __init__(self, timeout: float = 2.0, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency

    async def _check_port(self, host: str, port: int) -> PortResult:
        """Probe a single TCP port with optional banner grab.

        Args:
            host: Target hostname or IP.
            port: TCP port number.

        Returns:
            PortResult with state 'open' or 'closed'.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            service = self._guess_service(port)
            return PortResult(host=host, port=port, state="closed", service_guess=service, banner="")

        # Banner grab — best-effort with short timeout
        banner = ""
        try:
            raw = await asyncio.wait_for(reader.read(256), timeout=1.0)
            banner = raw.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        service = self._guess_service(port)
        return PortResult(host=host, port=port, state="open", service_guess=service, banner=banner)

    def _guess_service(self, port: int) -> str:
        """Return a service name guess for a port."""
        if port in _RISKY_PORTS:
            return _RISKY_PORTS[port][0]
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    async def _scan_async(self, host: str, ports: list[int]) -> list[PortResult]:
        """Scan all ports concurrently with a semaphore throttle."""
        sem = asyncio.Semaphore(self.concurrency)

        async def _limited(p: int) -> PortResult:
            async with sem:
                return await self._check_port(host, p)

        tasks = [_limited(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid: list[PortResult] = []
        for r in results:
            if isinstance(r, PortResult):
                valid.append(r)
        return valid

    def scan(self, host: str, ports: Optional[list[int]] = None) -> tuple[list[PortResult], list[PortFinding]]:
        """Run a synchronous port scan returning results and risk findings.

        Args:
            host: Target hostname or IP address.
            ports: List of ports to scan. Defaults to TOP_100_PORTS.

        Returns:
            Tuple of (all_results, findings_for_risky_open_ports).
        """
        if ports is None:
            ports = list(TOP_100_PORTS)

        results = asyncio.run(self._scan_async(host, ports))

        findings: list[PortFinding] = []
        for r in results:
            if r.state != "open":
                continue
            if r.port not in _RISKY_PORTS:
                continue
            service_name, severity, description = _RISKY_PORTS[r.port]
            evidence = f"Port {r.port}/{service_name} is open"
            if r.banner:
                evidence += f" | Banner: {r.banner}"
            findings.append(PortFinding(
                host=r.host,
                port=r.port,
                service=service_name,
                finding=description,
                severity=severity,
                evidence=evidence,
                cwe="CWE-200",
            ))

        return results, findings
