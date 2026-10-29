from werkzeug.security import generate_password_hash
from app import connect_db, init_db

init_db()
accounts = [
    ('CyberShield Administrator', 'admin@cybershield.local', 'Admin@123', 'admin'),
    ('Security Engineer', 'engineer@cybershield.local', 'Engineer@123', 'engineer'),
    ('Demo Complainer', 'customer@cybershield.local', 'Customer@123', 'complainer'),
]
con = connect_db()
for name, email, password, role in accounts:
    row = con.execute('SELECT user_id FROM users WHERE lower(email)=lower(?)', (email,)).fetchone()
    password_hash = generate_password_hash(password)
    if row:
        con.execute('UPDATE users SET full_name=?, email=?, password_hash=?, role=?, is_active=1 WHERE user_id=?',
                    (name, email, password_hash, role, row['user_id']))
    else:
        con.execute('INSERT INTO users(full_name,email,password_hash,role,is_active) VALUES(?,?,?,?,1)',
                    (name, email, password_hash, role))
con.commit()
con.close()
print('Demo login accounts repaired and enabled. Existing incident and evidence records were preserved.')
print('Admin: admin@cybershield.local / Admin@123')
print('Engineer: engineer@cybershield.local / Engineer@123')
print('Customer: customer@cybershield.local / Customer@123')
