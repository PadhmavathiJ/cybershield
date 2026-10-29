import pytest
import services

class FakeCursor:
    def __init__(self):
        self.description = [("USER_ID",), ("FULL_NAME",)]
        self.executed = None
        self.closed = False

    def execute(self, sql, params):
        self.executed = (sql, params)

    def fetchall(self):
        return [(7, "Test User")]

    def close(self):
        self.closed = True

class FakeConnection:
    def __init__(self):
        self.cursor_obj = FakeCursor()
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True

def test_fetch_all_uses_bound_parameters(monkeypatch):
    con = FakeConnection()
    monkeypatch.setattr(services, "get_connection", lambda: con)
    result = services.fetch_all(
        "SELECT user_id, full_name FROM app_user WHERE user_id = :user_id",
        {"user_id": 7}
    )
    assert result == [{"user_id": 7, "full_name": "Test User"}]
    assert con.cursor_obj.executed[1] == {"user_id": 7}
    assert con.closed
    assert con.cursor_obj.closed

@pytest.mark.parametrize("name", [
    "bad name",
    "APP_USER; DROP TABLE APP_USER",
    "APP_USER--"
])
def test_invalid_database_object_name_is_rejected(name):
    with pytest.raises(ValueError):
        services._check_name(name)