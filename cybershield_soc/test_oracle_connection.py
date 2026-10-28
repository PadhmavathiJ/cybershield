
from db import get_connection, close_pool


def main():
    con = None
    cur = None

    try:
        con = get_connection()
        cur = con.cursor()
        cur.execute("SELECT 1 FROM dual")
        result = cur.fetchone()

        if result[0] != 1:
            raise RuntimeError("Unexpected Oracle test result")

        print("Oracle connection pool test passed")

    finally:
        if cur is not None:
            cur.close()

        if con is not None:
            con.close()

        close_pool()


if __name__ == "__main__":
    main()
