"""Redis optional-startup behavior."""

import logging

from modules.db_manager import DASTDatabase, _RedisStore


def test_redis_store_disabled_without_url_does_not_log_unavailable(caplog):
    caplog.set_level(logging.INFO, logger="dast.db")

    store = _RedisStore(None)

    assert store.available is False
    assert "Redis] Unavailable" not in caplog.text


def test_database_default_does_not_probe_redis_without_env(monkeypatch, caplog):
    monkeypatch.delenv("REDIS_URL", raising=False)
    caplog.set_level(logging.INFO, logger="dast.db")

    db = DASTDatabase(redis_url=None)

    assert db.redis.available is False
    assert "Redis] Unavailable" not in caplog.text
