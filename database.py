import sqlite3

def get_connection():
    connection = sqlite3.connect("scanner.db")
    return connection

def init_db():
    connection = get_connection()
    cursor = connection.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            repo TEXT,
            scanned_at TEXT,
            skipped_count INTEGER
        )
    """)
    
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN findings_count INTEGER")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN risk_score INTEGER")
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        created_at TEXT
    )
""")

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN github_id INTEGER")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
    except sqlite3.OperationalError:
        pass
    
    connection.commit()
    connection.close()


def save_scan(owner, repo, findings, skipped_count, risk_score, user_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO scans (owner, repo, scanned_at, skipped_count, findings_count, risk_score, user_id) VALUES (?, ?, datetime('now'), ?, ?, ?, ?)",
        (owner, repo, skipped_count, len(findings), risk_score, user_id)
    )
    
    scan_id = cursor.lastrowid
    
    for finding in findings:
        severity = "HIGH" if finding["method"] == "pattern" else "MEDIUM"
        cursor.execute(
            "INSERT INTO findings (scan_id, file, type, match, method, severity) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, finding["file"], finding["type"], finding["match"], finding["method"], severity)
        )
    
    connection.commit()
    connection.close()
    return scan_id

def get_all_scans(user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT id, owner, repo, scanned_at, skipped_count FROM scans WHERE user_id = ? ORDER BY scanned_at DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    connection.close()
    return rows

def create_user(email, password_hash):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, datetime('now'))",
        (email, password_hash)
    )
    user_id = cursor.lastrowid
    connection.commit()
    connection.close()
    return user_id


def get_user_by_email(email):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    connection.close()
    return row

def get_scan_findings(scan_id, user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT user_id FROM scans WHERE id = ?", (scan_id,))
    owner_row = cursor.fetchone()
    if not owner_row or owner_row[0] != user_id:
        connection.close()
        return None
    cursor.execute("SELECT file, type, match, method, severity FROM findings WHERE scan_id = ?", (scan_id,))
    rows = cursor.fetchall()
    connection.close()
    return rows

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
    fake_findings = [
        {"file": "config.py", "type": "Slack Token", "match": "xoxb-fake", "method": "pattern"}
    ]
    scan_id = save_scan("testowner", "testrepo", fake_findings, 0)
    print("Saved scan with id:", scan_id)
    
    print(get_all_scans())
    print(get_scan_findings(scan_id))

def get_scan_history_for_repo(owner, repo, user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT scanned_at, findings_count, risk_score FROM scans WHERE owner = ? AND repo = ? AND user_id = ? ORDER BY scanned_at ASC",
        (owner, repo, user_id)
    )
    rows = cursor.fetchall()
    connection.close()
    return rows

def clear_scans_for_repo(owner, repo, user_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM scans WHERE owner = ? AND repo = ? AND user_id = ?",
        (owner, repo, user_id)
    )
    scan_ids = [row[0] for row in cursor.fetchall()]

    for scan_id in scan_ids:
        cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))

    cursor.execute(
        "DELETE FROM scans WHERE owner = ? AND repo = ? AND user_id = ?",
        (owner, repo, user_id)
    )

    connection.commit()
    connection.close()

def get_user_by_github_id(github_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, email, password_hash, github_id FROM users WHERE github_id = ?", (github_id,))
    row = cursor.fetchone()
    connection.close()
    return row


def create_user_from_github(email, github_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, github_id, created_at) VALUES (?, NULL, ?, datetime('now'))",
        (email, github_id)
    )
    user_id = cursor.lastrowid
    connection.commit()
    connection.close()
    return user_id


def link_github_to_user(user_id, github_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET github_id = ? WHERE id = ?", (github_id, user_id))
    connection.commit()
    connection.close()
    