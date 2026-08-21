import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    is_new = not os.path.exists(DB_PATH)
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS guestbook (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()

    if is_new:
        # NOT: sifreler bilerek duz metin tutuluyor (VULNERABILITIES.md #2/#8) --
        # boylece klasik "SQLi ile login bypass" senaryosu tek bir raw SQL sorgusunda gosterilebiliyor.
        cur.executemany(
            "INSERT INTO users (username, password, email, role, notes) VALUES (?, ?, ?, ?, ?)",
            [
                (
                    "admin",
                    "admin123",
                    "admin@pentestlab.local",
                    "admin",
                    "Ic not: bu hesabin sifresi hic rotate edilmedi.",
                ),
                ("ayse", "ayse2024", "ayse@example.com", "user", ""),
                ("mehmet", "mehmet2024", "mehmet@example.com", "user", ""),
            ],
        )
        cur.executemany(
            "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
            [
                ("Kablosuz Klavye", "Sessiz tuslu kablosuz klavye", 450.0),
                ("USB-C Hub", "7 in 1 USB-C cogaltici", 620.0),
                ("Mekanik Mouse", "RGB aydinlatmali oyuncu faresi", 890.0),
                ("Laptop Standi", "Aluminyum, ayarlanabilir yukseklik", 350.0),
            ],
        )
        cur.executemany(
            "INSERT INTO guestbook (author, message) VALUES (?, ?)",
            [
                ("ziyaretci1", "Harika bir urun, tesekkurler!"),
                ("ziyaretci2", "Kargo hizliydi, memnun kaldim."),
            ],
        )
        conn.commit()

    conn.close()
