import os
import tempfile

_fd, _test_db_path = tempfile.mkstemp(suffix=".db", prefix="sentinelurl-tests-")
os.close(_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"


def pytest_sessionfinish(session, exitstatus):
    try:
        from app.db.database import engine

        engine.dispose()
        os.unlink(_test_db_path)
    except (ImportError, FileNotFoundError):
        pass
