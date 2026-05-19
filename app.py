from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "secretkey"

# ---------- Database ----------
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password BLOB,
    role TEXT
)
""")

conn.commit()
conn.close()

# ---------- Register ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]

        password = bcrypt.hashpw(
            request.form["password"].encode(),
            bcrypt.gensalt()
        )

        role = request.form["role"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password, role)
        )

        conn.commit()
        conn.close()

        return redirect("/")

    return render_template("register.html")

# ---------- Login ----------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(
            password.encode(),
            user[2]
        ):
            session["user"] = username
            session["role"] = user[3]

            return redirect("/dashboard")

    return render_template("login.html")

# ---------- Dashboard ----------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    return render_template(
        "dashboard.html",
        username=session["user"],
        role=session["role"]
    )

# ---------- Admin Panel ----------
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect("/")

    if session["role"] != "admin":
        return "Access Denied"

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT username, role FROM users")
    users = cursor.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        users=users
    )

# ---------- Logout ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------- Run ----------
if __name__ == "__main__":
    app.run(debug=True)
