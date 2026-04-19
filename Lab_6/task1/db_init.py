import pymysql
from config import *

def init_db():
    conn = pymysql.connect(host="127.0.0.1",port=3306,user=DB_USER,password=DB_PASSWORD,cursorclass=pymysql.cursors.DictCursor,autocommit=True)

    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        cur.execute(f"USE {DB_NAME}")
        cur.execute("""CREATE TABLE IF NOT EXISTS employees (id INT PRIMARY KEY, name VARCHAR(120), email VARCHAR(180) )""")
        cur.execute("SELECT COUNT(*) AS c FROM employees")
        count = cur.fetchone()["c"]
        if count == 0:
            cur.execute("INSERT INTO employees VALUES(%s, %s, %s)",(1, "Utkarsh", "utkarsh_k@cs.iitr.ac.in"))
            cur.execute("INSERT INTO employees VALUES(%s, %s, %s)",(2, "Adesh", "adesh_kp@cs.iitr.ac.in"))

    conn.close()
    print("DB initialized")

init_db()
