import re
from db import get_connection

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]*(\.[A-Za-z][A-Za-z0-9_$#]*)?$")

def _check_name(name):
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("Invalid database object name")
    return name

def fetch_all(sql, params=None):
    con = get_connection()
    cur = None
    try:
        cur = con.cursor()
        cur.execute(sql, params or {})
        cols = [d[0].lower() for d in cur.description]
        rows = cur.fetchall()
        result = []
        for row in rows:
            item = {}
            for key, value in zip(cols, row):
                if hasattr(value, "read"):
                    value = value.read()
                item[key] = value
            result.append(item)
        return result
    finally:
        if cur is not None:
            cur.close()
        con.close()

def fetch_one(sql, params=None):
    rows = fetch_all(sql, params)
    return rows[0] if rows else None

def execute_procedure(name, params, actor_id):
    name = _check_name(name)
    if actor_id is None:
        raise PermissionError("Authenticated actor required")
    con = get_connection()
    cur = None
    try:
        con.client_identifier = str(actor_id)
        cur = con.cursor()
        cur.callproc(name, params)
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        if cur is not None:
            cur.close()
        try:
            con.client_identifier = ""
        finally:
            con.close()