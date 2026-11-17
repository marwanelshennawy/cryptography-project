from flask import Flask, request, session, jsonify, send_from_directory
import os
import sqlite3
from werkzeug.utils import secure_filename
from datetime import timedelta
import shutil
import json

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)

BASE_UPLOAD_PATH = os.path.expanduser("~/storage")

ALLOWED_EXTENSIONS = {"txt"}


def init_db():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            used_storage_bytes INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            filesize INTEGER,
            original_name TEXT,
            stored_name TEXT,
            UNIQUE(username, original_name)
        )
    """)

    conn.commit()
    conn.close()


init_db()


def allowed_file(filename):
    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/sign-up", methods=["POST"])
def sign_up():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username, ))
    if cursor.fetchone():
        return jsonify({"message": "Username already exists"}), 409

    user_folder = os.path.join(BASE_UPLOAD_PATH, username)
    os.makedirs(user_folder, exist_ok=True)

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

    session["username"] = username
    session.permanent = True

    return jsonify({"message": "User created successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        session["username"] = username
        session.permanent = True
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/upload", methods=["POST"])
def upload_file():
    username = session.get("username")

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json

    filename = data.get("filename")
    encrypted_package = data.get("data")
    file_size = int(data.get("size", 0))

    if not filename or not encrypted_package:
        return jsonify({"error": "Missing encrypted data"}), 400

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT used_storage_bytes FROM users WHERE username=?", (username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    used_storage_bytes = row[0]

    original_name = filename
    stored_name = secure_filename(original_name)

    cursor.execute("SELECT filesize FROM files WHERE username=? AND original_name=?", (username, original_name))

    existing_file = cursor.fetchone()

    old_file_size = 0
    if existing_file:
        old_file_size = existing_file[0]

    new_total_storage = used_storage_bytes - old_file_size + file_size

    if new_total_storage > 209715200:
        conn.close()
        return jsonify({"error": "There isn't enough storage for this file"}), 403

    user_folder = os.path.join(BASE_UPLOAD_PATH, username)
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, stored_name)
    with open(file_path, "w") as file:
        json.dump(encrypted_package, file, indent=4)

    try:
        if existing_file:
            cursor.execute("UPDATE files SET filesize=?, stored_name=? WHERE username=? AND original_name=?",
                           (file_size, stored_name, username, original_name))

        else:
            cursor.execute("INSERT INTO files (username, filesize, original_name, stored_name) VALUES (?, ?, ?, ?)"
                           , (username, file_size, original_name, stored_name))

        cursor.execute("UPDATE users SET used_storage_bytes=? WHERE username=?", (new_total_storage, username))
        conn.commit()

    except Exception as e:
        conn.rollback()

        if os.path.exists(file_path):
            os.remove(file_path)

        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()

    return jsonify({"message": "File uploaded successfully"}), 200


@app.route("/retrieve", methods=["GET"])
def retrieve_file():
    username = session.get("username")

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    original_name = request.args.get("filename")
    username = session["username"]

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT stored_name FROM files WHERE username=? AND original_name=?", (username, original_name))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "File not found"}), 404

    stored_name = row[0]

    user_folder = os.path.join(BASE_UPLOAD_PATH, username)
    file_path = os.path.join(user_folder, stored_name)

    if not os.path.exists(file_path):
        return jsonify({"error": "File missing on server"}), 404

    return send_from_directory(user_folder, stored_name, as_attachment=True)


@app.route("/delete", methods=["POST"])
def delete_file():
    username = session.get("username")

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    original_name = data.get("filename")
    username = session["username"]

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT stored_name, filesize FROM files WHERE username=? AND original_name=?",
                   (username, original_name))

    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"message": "Failure", "reason": "File not found in database"}), 404

    stored_name, file_size = row

    user_folder = os.path.join(BASE_UPLOAD_PATH, username)
    file_path = os.path.join(user_folder, stored_name)

    try:
        if os.path.exists(file_path):
            os.remove(file_path)

        cursor.execute("""DELETE FROM files WHERE username=? AND original_name=? """, (username, original_name))

        cursor.execute("UPDATE users SET used_storage_bytes = used_storage_bytes - ? WHERE username=? ",
                       (file_size, username))

        conn.commit()
        conn.close()

        return jsonify({"message": "Success"}), 200

    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"message": "Failure", "reason": str(e)}), 500


@app.route("/retrieve-files-names", methods=["GET"])
def retrieve_files_names():
    username = session.get("username")

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    username = session["username"]

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT original_name, filesize FROM files WHERE username=?", (username,))
    rows = cursor.fetchall()

    conn.close()

    return jsonify({"files": [row[0] for row in rows], "corresponding-sizes": [row[1] for row in rows]}), 200


@app.route("/delete-account", methods=["POST"])
def delete_account():
    username = session.get("username")

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    username = session["username"]

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    try:
        user_folder = os.path.join(BASE_UPLOAD_PATH, username)

        cursor.execute("DELETE FROM files WHERE username=?", (username,))

        cursor.execute("DELETE FROM users WHERE username=?", (username,))

        conn.commit()
        conn.close()

        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)

        session.clear()

        return jsonify({"message": "Account deleted successfully"}), 200

    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)