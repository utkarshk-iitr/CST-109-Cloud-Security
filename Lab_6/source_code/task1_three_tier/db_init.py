import pymysql
from config import *

def init_db():
    conn = pymysql.connect(host=DB_HOST,port=DB_PORT,user=DB_USER,password=DB_PASSWORD,cursorclass=pymysql.cursors.DictCursor,autocommit=True)

    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        cur.execute(f"USE {DB_NAME}")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(120) NOT NULL,
                email VARCHAR(180) NOT NULL UNIQUE
            )
        """)
        cur.execute("SELECT COUNT(*) AS c FROM employees")
        count = cur.fetchone()["c"]
        if count == 0:
            cur.execute(
                "INSERT INTO employees(name, email) VALUES(%s, %s)",
                ("alice", "alice@example.com"),
            )
            cur.execute(
                "INSERT INTO employees(name, email) VALUES(%s, %s)",
                ("bob", "bob@example.com"),
            )

    conn.close()
    print("DB initialized")

init_db()
