from db import get_connection

con = get_connection()
cur = con.cursor()

cur.execute("""
SELECT constraint_name, search_condition
FROM all_constraints
WHERE owner = 'CS_OWNER'
AND table_name = 'APP_USER'
AND constraint_name IN ('CK_USER_ROLE', 'CK_USER_ACTIVE', 'CK_USER_EMAIL_TRIM')
ORDER BY constraint_name
""")

for row in cur.fetchall():
    print(row)

cur.close()
con.close()
