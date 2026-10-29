from db import get_connection

con = get_connection()
cur = con.cursor()

cur.execute("""
SELECT column_name, data_type, nullable, data_default, identity_column
FROM all_tab_columns
WHERE owner = 'CS_OWNER' AND table_name = 'APP_USER'
ORDER BY column_id
""")

print("APP_USER COLUMNS:")
for row in cur.fetchall():
    print(row)

cur.execute("""
SELECT constraint_name, constraint_type, status
FROM all_constraints
WHERE owner = 'CS_OWNER' AND table_name = 'APP_USER'
ORDER BY constraint_type, constraint_name
""")

print("\nAPP_USER CONSTRAINTS:")
for row in cur.fetchall():
    print(row)

cur.close()
con.close()
