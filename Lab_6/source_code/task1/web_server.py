from flask import Flask, jsonify, request
import pymysql
from config import *

app = Flask(__name__)

def get_db_conn():
    return pymysql.connect(host=DB_HOST,port=DB_PORT,user=DB_USER,password=DB_PASSWORD,database=DB_NAME,cursorclass=pymysql.cursors.DictCursor,autocommit=True)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "SUCCESS", "service": "web", "port": WEB_PORT}), 200

@app.route("/employees", methods=["GET"])
def list_employees():
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, email FROM employees ORDER BY id")
            rows = cur.fetchall()
        return jsonify({"status": "SUCCESS", "data": rows}), 200
    except Exception as exc:
        return jsonify({"status": "ERROR", "message": str(exc)}), 500
    finally:
        if conn is not None:
            conn.close()

@app.route("/employees", methods=["POST"])
def add_employee():
    payload = request.get_json(silent=True) or {}
    id = int(str(payload.get("id", 0)).strip())
    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).strip()

    if name == "" or email == "":
        return jsonify({"status": "ERROR", "message": "name and email are required"}), 400

    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO employees VALUES(%s,%s, %s)",(id,name, email))

        return jsonify({
            "status": "SUCCESS","data": {"id": id, "name": name, "email": email}}), 201
    except Exception as exc:
        return jsonify({"status": "ERROR", "message": str(exc)}), 500
    finally:
        if conn is not None:
            conn.close()

app.run(host=WEB_HOST, port=WEB_PORT)
