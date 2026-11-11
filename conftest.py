import pytest

import main


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch, tmp_path):
    # Public deterministic key used ONLY in isolated test databases.
    monkeypatch.setenv("NOT_MY_KEY", "01" * 32)
    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "test.db"))
    main.initialize_database()
    main.ensure_keys()
