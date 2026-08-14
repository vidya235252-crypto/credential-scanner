import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])

def init_db():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            owner TEXT,
            repo TEXT,
            scanned_at TEXT,
            skipped_count INTEGER,
            findings_count INTEGER,
            risk_score INTEGER,
            user_id INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER,
            file TEXT,
            type TEXT,
            match TEXT,
            method TEXT,
            severity TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT,
            github_id INTEGER,
            github_access_token TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        ALTER TABLE users ADD COLUMN IF NOT EXISTS github_access_token TEXT
    """)

    connection.commit()
    cursor.close()
    connection.close()

def save_scan(owner, repo, findings, skipped_count, risk_score, user_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO scans (owner, repo, scanned_at, skipped_count, findings_count, risk_score, user_id) VALUES (%s, %s, NOW(), %s, %s, %s, %s) RETURNING id",
        (owner, repo, skipped_count, len(findings), risk_score, user_id)
    )
    scan_id = cursor.fetchone()[0]

    for finding in findings:
        severity = "HIGH" if finding["method"] == "pattern" else "MEDIUM"
        cursor.execute(
            "INSERT INTO findings (scan_id, file, type, match, method, severity) VALUES (%s, %s, %s, %s, %s, %s)",
            (scan_id, finding["file"], finding["type"], finding["match"], finding["method"], severity)
        )

    connection.commit()
    cursor.close()
    connection.close()
    return scan_id

def create_user(email, password_hash):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, created_at) VALUES (%s, %s, NOW()) RETURNING id",
        (email, password_hash)
    )
    user_id = cursor.fetchone()[0]
    connection.commit()
    cursor.close()
    connection.close()
    return user_id

def get_all_scans(user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT id, owner, repo, scanned_at, skipped_count FROM scans WHERE user_id = %s ORDER BY scanned_at DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    connection.close()
    return rows


def get_user_by_email(email):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, email, password_hash FROM users WHERE email = %s", (email,))
    row = cursor.fetchone()
    cursor.close()
    connection.close()
    return row


def get_scan_findings(scan_id, user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT user_id FROM scans WHERE id = %s", (scan_id,))
    owner_row = cursor.fetchone()
    if not owner_row or owner_row[0] != user_id:
        cursor.close()
        connection.close()
        return None
    cursor.execute("SELECT file, type, match, method, severity FROM findings WHERE scan_id = %s", (scan_id,))
    rows = cursor.fetchall()
    cursor.close()
    connection.close()
    return rows


def get_scan_history_for_repo(owner, repo, user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT scanned_at, findings_count, risk_score FROM scans WHERE owner = %s AND repo = %s AND user_id = %s ORDER BY scanned_at ASC",
        (owner, repo, user_id)
    )
    rows = cursor.fetchall()
    cursor.close()
    connection.close()
    return rows


def clear_scans_for_repo(owner, repo, user_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM scans WHERE owner = %s AND repo = %s AND user_id = %s",
        (owner, repo, user_id)
    )
    scan_ids = [row[0] for row in cursor.fetchall()]

    for scan_id in scan_ids:
        cursor.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))

    cursor.execute(
        "DELETE FROM scans WHERE owner = %s AND repo = %s AND user_id = %s",
        (owner, repo, user_id)
    )

    connection.commit()
    cursor.close()
    connection.close()


def create_user_from_github(email, github_id, github_access_token):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, github_id, github_access_token, created_at) VALUES (%s, NULL, %s, %s, NOW()) RETURNING id",
        (email, github_id, github_access_token)
    )
    user_id = cursor.fetchone()[0]
    connection.commit()
    cursor.close()
    connection.close()
    return user_id

def get_user_by_github_id(github_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, email, password_hash, github_id FROM users WHERE github_id = %s", (github_id,))
    row = cursor.fetchone()
    cursor.close()
    connection.close()
    return row

def link_github_to_user(user_id, github_id, github_access_token):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE users SET github_id = %s, github_access_token = %s WHERE id = %s",
        (github_id, github_access_token, user_id)
    )
    connection.commit()
    cursor.close()
    connection.close()


def get_github_access_token(user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT github_access_token FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    cursor.close()
    connection.close()
    return row[0] if row else None