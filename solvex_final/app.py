"""
==============================================
  SOLVEX-AI BACKEND  —  Python Flask + SQLite
==============================================
  Run:  python app.py
  URL:  http://localhost:5000
==============================================
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
import sqlite3, os, json, csv
import hashlib, hmac
from datetime import datetime, timedelta

app = Flask(__name__, template_folder="templates", static_folder="templates")

DB = "solvex.db"

# ── CORS ──
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/login", methods=["OPTIONS"])
@app.route("/register", methods=["OPTIONS"])
def handle_options():
    return "", 204


# ── PASSWORD HELPERS ──
def hash_password(password):
    """Hash password using SHA-256 with a salt"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()

def check_password(stored_password, provided_password):
    """Verify password against stored hash. Also handles legacy plain-text passwords."""
    # Handle BLOCKED_ prefix
    if stored_password.startswith('BLOCKED_'):
        return False
    # Check if it's a hashed password (contains ':')
    if ':' in stored_password and len(stored_password) > 80:
        try:
            salt_hex, key_hex = stored_password.split(':', 1)
            salt = bytes.fromhex(salt_hex)
            key = bytes.fromhex(key_hex)
            new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
            return hmac.compare_digest(key, new_key)
        except Exception:
            return False
    else:
        # Legacy plain-text comparison (for existing accounts)
        return stored_password == provided_password

# ── DATABASE ──
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        email       TEXT UNIQUE NOT NULL,
        mobile      TEXT,
        password    TEXT NOT NULL,
        role        TEXT NOT NULL,
        department  TEXT,
        company     TEXT,
        industry    TEXT,
        about       TEXT,
        city        TEXT,
        tech_stack  TEXT,
        budget_range TEXT,
        collab_type  TEXT,
        logo_data    TEXT,
        profile_updated_at DATETIME,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS problems (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        title       TEXT NOT NULL,
        description TEXT,
        category    TEXT,
        budget      TEXT,
        timeline    TEXT,
        difficulty  TEXT,
        provider    TEXT,
        provider_email TEXT,
        status      TEXT DEFAULT 'pending',
        faculty_accepted_by TEXT,
        student_accepted_by TEXT,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS projects (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        student_name   TEXT,
        student_email  TEXT,
        problem_id     INTEGER,
        description    TEXT,
        github         TEXT,
        progress       TEXT,
        team_members   TEXT,
        status         TEXT DEFAULT 'pending',
        faculty_remark TEXT,
        submitted_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS team_requests (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        from_email  TEXT,
        from_name   TEXT,
        to_email    TEXT,
        to_name     TEXT,
        message     TEXT,
        status      TEXT DEFAULT 'pending',
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS team_members (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        leader_email TEXT,
        member_email TEXT,
        member_name  TEXT,
        joined_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS accepted_problems (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email TEXT,
        problem_id    INTEGER,
        accepted_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS certificates (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email  TEXT,
        student_name   TEXT,
        project_id     INTEGER,
        issued_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    # ── EARNINGS TABLE ──
    c.execute("""CREATE TABLE IF NOT EXISTS earnings (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email    TEXT,
        user_role     TEXT,
        problem_id    INTEGER,
        project_id    INTEGER,
        budget        REAL,
        student_share REAL,
        faculty_share REAL,
        university_share REAL,
        month         TEXT,
        earned_at     DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    # Safe column migrations
    for col, typ in [
        ("about","TEXT"),("city","TEXT"),("tech_stack","TEXT"),
        ("budget_range","TEXT"),("collab_type","TEXT"),("logo_data","TEXT"),
        ("profile_updated_at","DATETIME")
    ]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        except:
            pass

    # Problems table migrations
    for col, typ in [("faculty_accepted_by","TEXT"),("student_accepted_by","TEXT")]:
        try:
            c.execute(f"ALTER TABLE problems ADD COLUMN {col} {typ}")
        except:
            pass

    conn.commit()
    conn.close()
    print("✅ Database ready — solvex.db")


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# ── STATIC FILES ──
@app.route("/Solvex-Ai-logo.png")
def logo_png():
    return send_from_directory(".", "Solvex-Ai-logo.png")

@app.route("/Solvex-Ai-logo.jpeg")
def logo_jpeg():
    return send_from_directory(".", "Solvex-Ai-logo.jpeg")


# ── PAGES ──
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/<path:page>")
def pages(page):
    if not page.endswith(".html"):
        page = page + ".html"
    try:
        return render_template(page)
    except:
        return "Page not found", 404


# ── AUTH ──
@app.route("/register", methods=["POST"])
def register():
    d = request.get_json()
    username   = d.get("username","").strip()
    email      = d.get("email","").strip().lower()
    mobile     = d.get("mobile","").strip()
    password   = d.get("password","").strip()
    role       = d.get("role","student").strip()
    department = d.get("department","")
    company    = d.get("company","")
    industry   = d.get("industry","")

    if not all([username, email, mobile, password]):
        return jsonify({"status":"error","message":"fill all fields❌"})

    # Password strength check
    if len(password) < 6:
        return jsonify({"status":"error","message":"Password must be at least 6 characters ❌"})

    # ===============================
    # ✅ ROLE BASED EMAIL VALIDATION
    # ===============================
    import re

    if role == "student":
        if not re.match(r"^[0-9]{4}.*@poornima\.edu\.in$", email):
            return jsonify({"status":"error","message":"Invalid student email ❌"})

    elif role == "faculty":
     name_part = email.split("@")[0]

     if not email.endswith("@poornima.edu.in") or email[:4].isdigit() or "." not in name_part:
        return jsonify({"status":"error","message":"Invalid  email/password ❌"})

    elif role == "provider":
        if email.endswith("@poornima.edu.in"):
            return jsonify({"status":"error","message":"Provider cannot use university email ❌"})

    elif role == "admin":
        if email != "solvexadmin2025@poornima.edu.in":
            return jsonify({"status":"error","message":"Invalid admin email ❌"})

    if role == "admin":
        if d.get("admin_code","") != "SOLVEX@ADMIN2025":
            return jsonify({"status":"error","message":"Admin Secret Code is incorrect ❌"})

    # Hash the password before storing
    hashed = hash_password(password)

    conn = db()
    try:
        conn.execute(
            "INSERT INTO users (username,email,mobile,password,role,department,company,industry) VALUES(?,?,?,?,?,?,?,?)",
            (username, email, mobile, hashed, role, department, company, industry)
        )
        conn.commit()
        return jsonify({"status":"success","message":"Account ban gaya ✅","username":username,"email":email,"role":role})
    except sqlite3.IntegrityError:
        return jsonify({"status":"error","message":"this email is already registered ❌"})
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    d = request.get_json()
    email    = d.get("email","").strip().lower()
    password = d.get("password","").strip()
    role     = d.get("role","").strip()

    if not all([email, password, role]):
        return jsonify({"status":"error","message":"fill all fields❌"})

    # ===============================
    # ✅ ROLE BASED EMAIL VALIDATION
    # ===============================
    import re

    if role == "student":
        if not re.match(r"^[0-9]{4}.*@poornima\.edu\.in$", email):
            return jsonify({"status":"error","message":"Invalid student email ❌"})

    elif role == "faculty":
     name_part = email.split("@")[0]

     if not email.endswith("@poornima.edu.in") or email[:4].isdigit() or "." not in name_part:
        return jsonify({"status":"error","message":"Invalid  email /password ❌"})

    elif role == "provider":
        if email.endswith("@poornima.edu.in"):
            return jsonify({"status":"error","message":"Provider cannot use university email ❌"})

    elif role == "admin":
        if email != "solvexadmin2025@poornima.edu.in":
            return jsonify({"status":"error","message":"Invalid admin email ❌"})

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"status":"error","message":"User not found ❌"})

    # Check if user is blocked
    if user["password"].startswith("BLOCKED_"):
        return jsonify({"status":"error","message":"Your account has been blocked. Please contact the administrator ❌"})

    if not check_password(user["password"], password):
        return jsonify({"status":"error","message":"Incorrect password ❌"})

    if user["role"] != role:
        return jsonify({"status":"error","message":f"Your account role is '{user['role']}', not '{role}' ❌"})

    return jsonify({
        "status":"success",
        "message":"Login ho gaya ✅",
        "username":user["username"],
        "email":user["email"],
        "role":user["role"]
    })

# ── PROFILE ──
@app.route("/get-profile")
def get_profile():
    email = request.args.get("email","").strip().lower()
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"status":"error","message":"User not found"})
    u = dict(user)
    u.pop("password", None)
    return jsonify(u)

@app.route("/update-profile", methods=["POST"])
def update_profile():
    d = request.get_json()
    email = d.get("email","").strip().lower()

    # ── 15-din restriction check ──
    conn = db()
    user = conn.execute("SELECT profile_updated_at FROM users WHERE email=?", (email,)).fetchone()
    if user and user["profile_updated_at"]:
        last_update = datetime.fromisoformat(user["profile_updated_at"])
        days_since = (datetime.now() - last_update).days
        if days_since < 15:
            days_left = 15 - days_since
            conn.close()
            return jsonify({
                "status": "error",
                "message": f"Profile update karne ke liye {days_left} din aur wait karein ⏳ (15 din baad update kar sakte hain)"
            })

    now_str = datetime.now().isoformat()
    conn.execute("""UPDATE users SET
        username=?, company=?, industry=?, about=?, city=?,
        mobile=?, tech_stack=?, budget_range=?, collab_type=?, logo_data=?,
        department=?, profile_updated_at=?
        WHERE email=?""",
        (d.get("username",""), d.get("company",""), d.get("industry",""),
         d.get("about",""), d.get("city",""), d.get("mobile",""),
         d.get("tech_stack",""), d.get("budget_range",""), d.get("collab_type",""),
         d.get("logo_data",""), d.get("department",""), now_str, email))
    conn.commit()
    conn.close()
    return jsonify({"status":"success","message":"Profile update ho gayi ✅"})

@app.route("/get-provider-profile")
def get_provider_profile():
    email = request.args.get("email","").strip().lower()
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    problems = conn.execute("SELECT * FROM problems WHERE provider_email=?", (email,)).fetchall()
    conn.close()
    if not user:
        return jsonify({})
    profile = dict(user)
    profile.pop("password", None)
    profile["companyName"]   = profile.get("company","")
    profile["contactPerson"] = profile.get("username","")
    profile["problems"]      = [dict(p) for p in problems]
    profile["totalInvest"]   = sum(int(p["budget"] or 0) for p in profile["problems"])
    return jsonify(profile)

@app.route("/update-provider-profile", methods=["POST"])
def update_provider_profile():
    d = request.get_json()
    email = d.get("email","").strip().lower()

    conn = db()
    user = conn.execute("SELECT profile_updated_at FROM users WHERE email=?", (email,)).fetchone()
    if user and user["profile_updated_at"]:
        last_update = datetime.fromisoformat(user["profile_updated_at"])
        days_since = (datetime.now() - last_update).days
        if days_since < 15:
            days_left = 15 - days_since
            conn.close()
            return jsonify({
                "status": "error",
                "message": f"Profile update ke liye {days_left} din aur wait karein ⏳"
            })

    now_str = datetime.now().isoformat()
    conn.execute("""UPDATE users SET
        company=?, industry=?, username=?, about=?, city=?,
        mobile=?, tech_stack=?, budget_range=?, collab_type=?, logo_data=?,
        profile_updated_at=?
        WHERE email=?""",
        (d.get("companyName",""), d.get("industry",""), d.get("contactPerson",""),
         d.get("about",""), d.get("city",""), d.get("mobile",""),
         d.get("techStack",""), d.get("budgetRange",""), d.get("collabType",""),
         d.get("logo",""), now_str, email))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})


# ── PROBLEMS ──
@app.route("/post-problem", methods=["POST"])
def post_problem():
    d = request.get_json()
    conn = db()
    user = conn.execute("SELECT username,company FROM users WHERE email=?", (d.get("provider_email",""),)).fetchone()
    provider_name = ""
    if user:
        provider_name = user["company"] or user["username"] or ""
    conn.execute(
        "INSERT INTO problems (title,description,category,budget,timeline,difficulty,provider,provider_email,status) VALUES(?,?,?,?,?,?,?,?,'pending')",
        (d.get("title"), d.get("description"), d.get("category"), d.get("budget"),
         d.get("timeline"), d.get("difficulty"), provider_name, d.get("provider_email"))
    )
    conn.commit()
    conn.close()
    return jsonify({"status":"success","message":"Problem post ho gayi ✅"})

@app.route("/add-problem", methods=["POST"])
def add_problem():
    return post_problem()

# ── PROBLEM VISIBILITY LOGIC ──
# Provider posts → status=pending, visible to ALL faculty
# Faculty accepts (faculty_accepted_by set) → visible only to that faculty
# Faculty approves → status=approved, faculty_accepted_by stays, visible to ALL students
# Student accepts (student_accepted_by set) → visible only to that student

@app.route("/get-problems")
def get_problems():
    """Students ke liye: approved problems jo kisi ne accept nahi ki"""
    student_email = request.args.get("student_email","")
    conn = db()
    if student_email:
        # Return approved problems that are NOT yet accepted by anyone
        # OR specifically accepted by this student (so they can still see it)
        # BUT hide from the "available" list once accepted — student sees it in active problems
        rows = conn.execute("""
            SELECT * FROM problems
            WHERE status='approved'
            AND (student_accepted_by IS NULL OR student_accepted_by='')
            ORDER BY created_at DESC
        """).fetchall()
    else:
        rows = conn.execute("SELECT * FROM problems WHERE status='approved' ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/get-all-problems")
def get_all_problems():
    """Faculty/Admin ke liye sab problems"""
    faculty_email = request.args.get("faculty_email","")
    conn = db()
    if faculty_email:
        # Faculty ko: pending problems jo kisi ne accept nahi ki OR jo iss faculty ne accept ki
        # + approved/rejected problems
        rows = conn.execute("""
            SELECT * FROM problems
            WHERE status IN ('approved','rejected')
            OR (status='pending' AND (faculty_accepted_by IS NULL OR faculty_accepted_by='' OR faculty_accepted_by=?))
            ORDER BY created_at DESC
        """, (faculty_email,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM problems ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/get-my-problems")
def get_my_problems():
    email = request.args.get("email","")
    conn = db()
    rows = conn.execute("SELECT * FROM problems WHERE provider_email=? ORDER BY created_at DESC",(email,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/get-pending-problems")
def get_pending_problems():
    """Faculty ko pending problems: jo kisi ne accept nahi ki ya jo iss faculty ne accept ki"""
    faculty_email = request.args.get("faculty_email","")
    conn = db()
    if faculty_email:
        rows = conn.execute("""
            SELECT * FROM problems
            WHERE status='pending'
            AND (faculty_accepted_by IS NULL OR faculty_accepted_by='' OR faculty_accepted_by=?)
            ORDER BY created_at DESC
        """, (faculty_email,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM problems WHERE status='pending' ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/faculty-accept-problem", methods=["POST"])
def faculty_accept_problem():
    """Faculty kisi problem ko accept kare - sirf usi faculty ko dikhe"""
    d = request.get_json()
    pid = d.get("problem_id")
    faculty_email = d.get("faculty_email","")
    conn = db()
    # Check if already accepted by another faculty
    prob = conn.execute("SELECT faculty_accepted_by FROM problems WHERE id=?", (pid,)).fetchone()
    if prob and prob["faculty_accepted_by"] and prob["faculty_accepted_by"] != faculty_email:
        conn.close()
        return jsonify({"status":"error","message":"Yeh problem kisi aur faculty ne already accept kar li hai ❌"})
    conn.execute("UPDATE problems SET faculty_accepted_by=? WHERE id=?", (faculty_email, pid))
    conn.commit()
    conn.close()
    return jsonify({"status":"success","message":"Problem accept kar li ✅ Ab sirf aap dekh sakte ho ise"})

@app.route("/approve-problem", methods=["POST"])
def approve_problem():
    d = request.get_json()
    pid = d.get("problem_id") or d.get("id")
    faculty_email = d.get("faculty_email","")
    conn = db()
    # Set status approved, keep faculty_accepted_by
    if faculty_email:
        conn.execute("UPDATE problems SET status='approved', faculty_accepted_by=? WHERE id=?", (faculty_email, pid))
    else:
        conn.execute("UPDATE problems SET status='approved' WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/reject-problem", methods=["POST"])
def reject_problem():
    d = request.get_json()
    pid = d.get("problem_id") or d.get("id")
    conn = db()
    conn.execute("UPDATE problems SET status='rejected' WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/delete-problem", methods=["POST"])
def delete_problem():
    d = request.get_json()
    conn = db()
    conn.execute("DELETE FROM problems WHERE id=?", (d.get("problem_id"),))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/accept-problem", methods=["POST"])
def accept_problem():
    """Student problem accept kare - sirf usi student ko dikhe, approved section se hat jaye"""
    d = request.get_json()
    student_email = d.get("student_email","")
    problem_id    = d.get("problem_id")
    conn = db()

    # Check if already accepted by another student
    prob = conn.execute("SELECT student_accepted_by FROM problems WHERE id=?", (problem_id,)).fetchone()
    if prob and prob["student_accepted_by"] and prob["student_accepted_by"] != student_email:
        conn.close()
        return jsonify({"status":"error","message":"Yeh problem kisi aur student ne already accept kar li hai ❌"})

    # Mark problem as accepted by this student (hides from others)
    conn.execute("UPDATE problems SET student_accepted_by=? WHERE id=?", (student_email, problem_id))

    # Also add to accepted_problems table
    existing = conn.execute("SELECT * FROM accepted_problems WHERE student_email=? AND problem_id=?",
                            (student_email, problem_id)).fetchone()
    if not existing:
        conn.execute("INSERT INTO accepted_problems (student_email,problem_id) VALUES(?,?)",
                     (student_email, problem_id))
    conn.commit()
    conn.close()
    return jsonify({"status":"success","message":"Problem accept ho gayi ✅"})

@app.route("/get-accepted-problems")
def get_accepted_problems():
    email = request.args.get("email","")
    conn = db()
    rows = conn.execute("""
        SELECT p.*, ap.accepted_at
        FROM problems p
        JOIN accepted_problems ap ON p.id = ap.problem_id
        WHERE ap.student_email=?
        ORDER BY ap.accepted_at DESC
    """, (email,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/assign-problem", methods=["POST"])
def assign_problem():
    d = request.get_json()
    student_email = d.get("student_email","")
    problem_id    = d.get("problem_id")
    conn = db()
    # Mark problem accepted by this student
    conn.execute("UPDATE problems SET student_accepted_by=? WHERE id=?", (student_email, problem_id))
    existing = conn.execute("SELECT * FROM accepted_problems WHERE student_email=? AND problem_id=?",
                            (student_email, problem_id)).fetchone()
    if not existing:
        conn.execute("INSERT INTO accepted_problems (student_email,problem_id) VALUES(?,?)",
                     (student_email, problem_id))
    conn.commit()
    conn.close()
    return jsonify({"status":"success","message":f"Problem assigned to {student_email}"})


# ── PROJECTS ──
@app.route("/submit-project", methods=["POST"])
def submit_project():
    d = request.get_json()
    members = d.get("team_members", [])
    if isinstance(members, list):
        members_str = ", ".join([m.get("email","") if isinstance(m,dict) else str(m) for m in members])
    else:
        members_str = str(members)
    problem_id = d.get("problem_id") or None
    conn = db()
    conn.execute(
        "INSERT INTO projects (student_name,student_email,problem_id,description,github,progress,team_members,status) VALUES(?,?,?,?,?,?,?,'pending')",
        (d.get("student_name"), d.get("student_email"), problem_id,
         d.get("description"), d.get("github"), d.get("progress"), members_str)
    )
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/get-projects")
def get_projects():
    conn = db()
    rows = conn.execute("""
        SELECT p.*, pr.title as problem_title, pr.provider_email, pr.provider as provider_name,
               pr.budget as problem_budget
        FROM projects p
        LEFT JOIN problems pr ON p.problem_id = pr.id
        ORDER BY p.submitted_at DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/get-my-projects")
def get_my_projects():
    email = request.args.get("email","")
    conn = db()
    rows = conn.execute("""
        SELECT p.*, pr.title as problem_title, pr.provider_email, pr.provider as provider_name
        FROM projects p
        LEFT JOIN problems pr ON p.problem_id = pr.id
        WHERE p.student_email=?
        ORDER BY p.submitted_at DESC
    """, (email,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/approve-project", methods=["POST"])
def approve_project():
    d = request.get_json()
    conn = db()
    conn.execute("UPDATE projects SET status='completed',faculty_remark=? WHERE id=?",
                 (d.get("remark","Approved by Faculty"), d.get("project_id")))
    conn.commit()

    # Auto issue certificate + earnings
    proj = conn.execute("""
        SELECT p.*, pr.budget as problem_budget, pr.provider_email,
               pr.faculty_accepted_by
        FROM projects p
        LEFT JOIN problems pr ON p.problem_id = pr.id
        WHERE p.id=?
    """, (d.get("project_id"),)).fetchone()

    if proj:
        # Issue certificate
        conn.execute("INSERT INTO certificates (student_email,student_name,project_id) VALUES(?,?,?)",
                     (proj["student_email"], proj["student_name"], proj["id"]))

        # Calculate earnings: 45% student, 25% faculty, 30% university
        budget = float(proj["problem_budget"] or 0)
        student_share    = round(budget * 0.45, 2)
        faculty_share    = round(budget * 0.25, 2)
        university_share = round(budget * 0.30, 2)
        month = datetime.now().strftime("%Y-%m")

        # Student earning record
        conn.execute("""INSERT INTO earnings
            (user_email,user_role,problem_id,project_id,budget,student_share,faculty_share,university_share,month)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (proj["student_email"], "student", proj["problem_id"], proj["id"],
             budget, student_share, faculty_share, university_share, month))

        # Faculty earning record
        faculty_email = d.get("faculty_email","") or (proj["faculty_accepted_by"] or "")
        if faculty_email:
            conn.execute("""INSERT INTO earnings
                (user_email,user_role,problem_id,project_id,budget,student_share,faculty_share,university_share,month)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (faculty_email, "faculty", proj["problem_id"], proj["id"],
                 budget, student_share, faculty_share, university_share, month))

        conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/reject-project", methods=["POST"])
def reject_project():
    d = request.get_json()
    conn = db()
    conn.execute("UPDATE projects SET status='rejected',faculty_remark=? WHERE id=?",
                 (d.get("remark","Rejected by Faculty"), d.get("project_id")))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/get-applications")
def get_applications():
    provider_email = request.args.get("email","")
    conn = db()
    if provider_email:
        rows = conn.execute("""
            SELECT p.*, pr.title as problem_title, pr.provider_email, pr.budget as problem_budget
            FROM projects p
            LEFT JOIN problems pr ON p.problem_id = pr.id
            WHERE pr.provider_email=?
            ORDER BY p.submitted_at DESC
        """, (provider_email,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM projects ORDER BY submitted_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── EARNINGS ──
@app.route("/get-earnings")
def get_earnings():
    email = request.args.get("email","")
    role  = request.args.get("role","student")
    conn = db()
    rows = conn.execute("""
        SELECT e.*, p.title as problem_title, p.budget as prob_budget
        FROM earnings e
        LEFT JOIN problems p ON e.problem_id = p.id
        WHERE e.user_email=? AND e.user_role=?
        ORDER BY e.earned_at DESC
    """, (email, role)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/get-earnings-summary")
def get_earnings_summary():
    email = request.args.get("email","")
    role  = request.args.get("role","student")
    conn = db()
    rows = conn.execute("""
        SELECT month,
               SUM(CASE WHEN user_role='student' THEN student_share ELSE 0 END) as my_earning_student,
               SUM(CASE WHEN user_role='faculty' THEN faculty_share ELSE 0 END) as my_earning_faculty,
               SUM(budget) as total_budget,
               COUNT(*) as projects_count
        FROM earnings
        WHERE user_email=? AND user_role=?
        GROUP BY month
        ORDER BY month ASC
    """, (email, role)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── TEAM ──
@app.route("/send-team-request", methods=["POST"])
def send_team_request():
    d = request.get_json()
    conn = db()
    conn.execute(
        "INSERT INTO team_requests (from_email,from_name,to_email,to_name,message) VALUES(?,?,?,?,?)",
        (d.get("from_email"), d.get("from_name"), d.get("to_email"), d.get("to_name"), d.get("message"))
    )
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/get-team-requests")
def get_team_requests():
    email = request.args.get("email","")
    conn = db()
    rows = conn.execute("SELECT * FROM team_requests WHERE to_email=? ORDER BY created_at DESC",(email,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/respond-team-request", methods=["POST"])
def respond_team_request():
    d = request.get_json()
    req_id = d.get("request_id")
    action = d.get("action")
    student_email = d.get("student_email")
    conn = db()
    status = "accepted" if action == "accept" else "rejected"
    conn.execute("UPDATE team_requests SET status=? WHERE id=?", (status, req_id))
    if action == "accept":
        req = conn.execute("SELECT * FROM team_requests WHERE id=?", (req_id,)).fetchone()
        if req:
            existing = conn.execute("SELECT * FROM team_members WHERE leader_email=? AND member_email=?",
                                    (student_email, req["from_email"])).fetchone()
            if not existing:
                conn.execute("INSERT INTO team_members (leader_email,member_email,member_name) VALUES(?,?,?)",
                             (student_email, req["from_email"], req["from_name"]))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/get-team")
def get_team():
    email = request.args.get("email","")
    conn = db()
    rows = conn.execute("SELECT * FROM team_members WHERE leader_email=?",(email,)).fetchall()
    conn.close()
    return jsonify([{"email":r["member_email"],"name":r["member_name"]} for r in rows])

@app.route("/remove-team-member", methods=["POST"])
def remove_team_member():
    d = request.get_json()
    conn = db()
    conn.execute("DELETE FROM team_members WHERE leader_email=? AND member_email=?",
                 (d.get("team_leader"), d.get("member_email")))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})


# ── USERS ──
@app.route("/get-providers")
def get_providers():
    conn = db()
    rows = conn.execute("""SELECT id,username,email,mobile,company,industry,
                           about,city,tech_stack,budget_range,collab_type,logo_data,created_at
                           FROM users WHERE role='provider' ORDER BY created_at DESC""").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/get-students")
def get_students():
    conn = db()
    rows = conn.execute("""SELECT id,username,email,mobile,department,created_at
                           FROM users WHERE role='student' ORDER BY created_at DESC""").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── CERTIFICATES ──
@app.route("/issue-certificate", methods=["POST"])
def issue_certificate():
    d = request.get_json()
    conn = db()
    conn.execute("INSERT INTO certificates (student_email,student_name) VALUES(?,?)",
                 (d.get("student_email"), d.get("student_name")))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/get-certificates")
def get_certificates():
    email = request.args.get("email","")
    conn = db()
    if email:
        rows = conn.execute("SELECT * FROM certificates WHERE student_email=? ORDER BY issued_at DESC", (email,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM certificates ORDER BY issued_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── ADMIN ──
@app.route("/get-users")
def get_users():
    conn = db()
    rows = conn.execute("SELECT id,username,email,mobile,role,department,company,created_at,password FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    result = []
    for r in rows:
        u = dict(r)
        u["is_blocked"] = 1 if (u.get("password","") or "").startswith("BLOCKED_") else 0
        del u["password"]
        result.append(u)
    return jsonify(result)

@app.route("/admin/users")
def admin_users():
    return get_users()

@app.route("/admin/stats")
def admin_stats():
    conn = db()
    users    = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    problems = conn.execute("SELECT COUNT(*) FROM problems").fetchone()[0]
    projects = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
    approved = conn.execute("SELECT COUNT(*) FROM problems WHERE status='approved'").fetchone()[0]
    completed= conn.execute("SELECT COUNT(*) FROM projects WHERE status='completed'").fetchone()[0]
    conn.close()
    return jsonify({"users":users,"problems":problems,"projects":projects,"approved":approved,"completed":completed})

@app.route("/admin/revenue")
def admin_revenue():
    """Admin ke liye complete revenue chart data"""
    conn = db()

    # Monthly breakdown
    monthly = conn.execute("""
        SELECT
          month,
          SUM(budget)           as total_budget,
          SUM(student_share)    as total_student,
          SUM(faculty_share)    as total_faculty,
          SUM(university_share) as total_university,
          COUNT(DISTINCT project_id) as projects_count
        FROM earnings
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()

    # Overall totals
    totals = conn.execute("""
        SELECT
          COALESCE(SUM(budget),0)           as grand_total,
          COALESCE(SUM(student_share),0)    as student_total,
          COALESCE(SUM(faculty_share),0)    as faculty_total,
          COALESCE(SUM(university_share),0) as university_total,
          COUNT(DISTINCT project_id)        as total_projects,
          COUNT(DISTINCT user_email)        as total_earners
        FROM earnings
    """).fetchone()

    # Per-student breakdown
    students = conn.execute("""
        SELECT e.user_email, u.username,
               SUM(e.student_share) as earned,
               COUNT(*) as projects
        FROM earnings e
        LEFT JOIN users u ON e.user_email = u.email
        WHERE e.user_role='student'
        GROUP BY e.user_email
        ORDER BY earned DESC
        LIMIT 10
    """).fetchall()

    # Per-faculty breakdown
    faculty = conn.execute("""
        SELECT e.user_email, u.username,
               SUM(e.faculty_share) as earned,
               COUNT(*) as projects
        FROM earnings e
        LEFT JOIN users u ON e.user_email = u.email
        WHERE e.user_role='faculty'
        GROUP BY e.user_email
        ORDER BY earned DESC
        LIMIT 10
    """).fetchall()

    conn.close()
    return jsonify({
        "monthly":    [dict(r) for r in monthly],
        "totals":     dict(totals),
        "students":   [dict(r) for r in students],
        "faculty":    [dict(r) for r in faculty]
    })

@app.route("/admin/delete-user", methods=["POST"])
def admin_delete_user():
    d = request.get_json()
    email = d.get("email","")
    user_id = d.get("user_id")
    conn = db()
    if email:
        conn.execute("DELETE FROM users WHERE email=?", (email,))
    elif user_id:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/admin/add-user", methods=["POST"])
def admin_add_user():
    d = request.get_json()
    conn = db()
    try:
        raw_pass = d.get("password","solvex123")
        conn.execute(
            "INSERT INTO users (username,email,mobile,password,role,department,company) VALUES(?,?,?,?,?,?,?)",
            (d.get("name",""), d.get("email",""), d.get("mobile",""), hash_password(raw_pass),
             d.get("role","student"), d.get("department",""), d.get("company",""))
        )
        conn.commit()
        return jsonify({"status":"success"})
    except sqlite3.IntegrityError:
        return jsonify({"status":"error","message":"Email already exists"})
    finally:
        conn.close()

@app.route("/admin/block-user", methods=["POST"])
def admin_block_user():
    # We store blocked status in a simple way — password prefix
    d = request.get_json()
    email = d.get("email","")
    conn = db()
    user = conn.execute("SELECT password FROM users WHERE email=?", (email,)).fetchone()
    if user:
        pwd = user["password"]
        if not pwd.startswith("BLOCKED_"):
            conn.execute("UPDATE users SET password=? WHERE email=?", ("BLOCKED_"+pwd, email))
            conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/admin/approve-user", methods=["POST"])
def admin_approve_user():
    d = request.get_json()
    email = d.get("email","")
    conn = db()
    user = conn.execute("SELECT password FROM users WHERE email=?", (email,)).fetchone()
    if user:
        pwd = user["password"]
        if pwd.startswith("BLOCKED_"):
            conn.execute("UPDATE users SET password=? WHERE email=?", (pwd[8:], email))
            conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/admin/delete-problem", methods=["POST"])
def admin_delete_problem():
    d = request.get_json()
    pid = d.get("id") or d.get("problem_id")
    conn = db()
    conn.execute("DELETE FROM problems WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/admin/delete-certificate", methods=["POST"])
def admin_delete_certificate():
    d = request.get_json()
    conn = db()
    conn.execute("DELETE FROM certificates WHERE id=?", (d.get("id"),))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/get-messages")
def get_messages():
    conn = db()
    try:
        rows = conn.execute("SELECT * FROM contact_messages ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    except:
        return jsonify([])
    finally:
        conn.close()

@app.route("/admin/delete-message", methods=["POST"])
def admin_delete_message():
    d = request.get_json()
    conn = db()
    try:
        conn.execute("DELETE FROM contact_messages WHERE id=?", (d.get("id"),))
        conn.commit()
    except:
        pass
    finally:
        conn.close()
    return jsonify({"status":"success"})

@app.route("/admin/save-settings", methods=["POST"])
def admin_save_settings():
    # Settings saved in memory for now (can extend to DB)
    return jsonify({"status":"success"})

@app.route("/admin/send-reply", methods=["POST"])
def admin_send_reply():
    return jsonify({"status":"success", "message":"Reply feature needs SMTP config"})

@app.route("/admin/all-problems")
def admin_all_problems():
    conn = db()
    rows = conn.execute("SELECT * FROM problems ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── FORGOT PASSWORD (OTP via Gmail) ──
import smtplib, random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ⚠️ APNA GMAIL AUR APP PASSWORD YAHAN DAALO
SMTP_EMAIL    = "praveennama4957@gmail.com"
SMTP_PASSWORD = "jzno dwtj pgco ciav"   # Gmail App Password

otp_store = {}  # {email: {"otp": "123456", "expires": datetime}}

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    d = request.get_json()
    email = d.get("email","").strip().lower()

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"status":"error","message":"Yeh email registered nahi hai ❌"})

    otp = str(random.randint(100000, 999999))
    otp_store[email] = {"otp": otp, "expires": datetime.now() + timedelta(minutes=10)}

    # Send OTP email
    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = f"Solvex-AI <{SMTP_EMAIL}>"
        msg["To"]      = email
        msg["Subject"] = "🔐 Solvex-AI — Password Reset OTP"

        html_body = f"""
<html><body style="font-family:Arial,sans-serif;background:#f8fafc;padding:30px">
<div style="max-width:480px;margin:0 auto;background:white;border-radius:16px;padding:32px;border:1px solid #e2e8f0">
  <div style="text-align:center;margin-bottom:24px">
    <h2 style="color:#6366f1;margin:0">Solvex-AI</h2>
    <p style="color:#64748b;font-size:13px;margin-top:4px">Poornima University</p>
  </div>
  <h3 style="color:#0f172a;margin-bottom:8px">Password Reset Request</h3>
  <p style="color:#64748b;font-size:14px">Namaste <b>{user['username']}</b>,</p>
  <p style="color:#64748b;font-size:14px">Aapne password reset ki request ki hai. Neeche diya OTP use karein:</p>
  <div style="background:#f1f5f9;border-radius:12px;padding:24px;text-align:center;margin:24px 0">
    <div style="font-size:40px;font-weight:900;letter-spacing:12px;color:#6366f1">{otp}</div>
    <p style="color:#94a3b8;font-size:12px;margin-top:8px">Yeh OTP <b>10 minutes</b> mein expire hoga</p>
  </div>
  <p style="color:#94a3b8;font-size:12px;margin-top:24px">Agar aapne yeh request nahi ki, to is email ko ignore karein. Aapka account safe hai.</p>
  <div style="border-top:1px solid #e2e8f0;margin-top:24px;padding-top:16px;text-align:center">
    <p style="color:#cbd5e1;font-size:11px">© Solvex-AI — Poornima University</p>
  </div>
</div>
</body></html>"""

        text_body = f"Namaste {user['username']}!\n\nAapka OTP: {otp}\n\nYeh 10 minutes mein expire hoga.\n\n— Solvex-AI Team"

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, email, msg.as_string())
        return jsonify({"status":"success","message":f"OTP bhej diya gaya {email} par ✅ Inbox check karein!"})
    except Exception as e:
        print(f"SMTP Error: {e}")
        return jsonify({"status":"error","message":f"Email nahi bheja ja saka. Server error: {str(e)}"}) 

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    d = request.get_json()
    email = d.get("email","").strip().lower()
    otp   = d.get("otp","").strip()

    record = otp_store.get(email)
    if not record:
        return jsonify({"status":"error","message":"OTP nahi mila. Pehle forgot password karein ❌"})
    if datetime.now() > record["expires"]:
        del otp_store[email]
        return jsonify({"status":"error","message":"OTP expire ho gaya. Dobara try karein ❌"})
    if record["otp"] != otp:
        return jsonify({"status":"error","message":"OTP galat hai ❌"})

    return jsonify({"status":"success","message":"OTP verify ho gaya ✅"})

@app.route("/reset-password", methods=["POST"])
def reset_password():
    d = request.get_json()
    email    = d.get("email","").strip().lower()
    otp      = d.get("otp","").strip()
    new_pass = d.get("new_password","").strip()

    record = otp_store.get(email)
    if not record or record["otp"] != otp:
        return jsonify({"status":"error","message":"OTP verify nahi hua ❌"})
    if datetime.now() > record["expires"]:
        return jsonify({"status":"error","message":"OTP expire ho gaya ❌"})
    if len(new_pass) < 6:
        return jsonify({"status":"error","message":"Password kam se kam 6 characters ka hona chahiye ❌"})

    conn = db()
    conn.execute("UPDATE users SET password=? WHERE email=?", (hash_password(new_pass), email))
    conn.commit()
    conn.close()
    del otp_store[email]
    return jsonify({"status":"success","message":"Password reset successfully ✅ Please login with your new password!"})


# ══════════════════════════════════════════════════════════════
#  CHATBOT — JSON + CSV dono se data load hota hai automatically
#
#  knowledge_base.json  →  JSON format mein data add karo
#  knowledge_base.csv   →  CSV format mein data add karo
#
#  Dono files ek saath kaam karti hain — jisme bhi keyword mile
#  wahan se reply aata hai. Kisi ek ya dono ko use kar sakte ho!
# ══════════════════════════════════════════════════════════════

BASE_DIR           = os.path.dirname(os.path.abspath(__file__))
KB_JSON            = os.path.join(BASE_DIR, "knowledge_base.json")
KB_CSV             = os.path.join(BASE_DIR, "knowledge_base.csv")
DEFAULT_REPLY      = "Yeh topic mere knowledge mein nahi hai 😅 Please contact: praveennama7665@gmail.com ya +91 9351360177"


def _load_json_kb():
    """
    knowledge_base.json supports bilingual replies:
    { "keywords": [...], "reply_en": "English reply", "reply_hi": "Hindi reply" }
    OR simple: { "keywords": [...], "reply": "..." }
    """
    entries = []
    if not os.path.exists(KB_JSON):
        return entries
    try:
        with open(KB_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            keywords = item.get("keywords", [])
            if isinstance(keywords, str):
                keywords = [k.strip() for k in keywords.split(",") if k.strip()]
            reply_en = item.get("reply_en", item.get("reply", "")).strip()
            reply_hi = item.get("reply_hi", reply_en).strip()
            if keywords and reply_en:
                entries.append({
                    "keywords": [k.lower() for k in keywords],
                    "reply_en": reply_en,
                    "reply_hi": reply_hi
                })
    except Exception as e:
        print(f"⚠️  knowledge_base.json load error: {e}")
    return entries


def _load_csv_kb():
    """
    knowledge_base.csv format:
    keywords,reply_en,reply_hi
    "hello,hi","Hello! I'm AIRA","Namaste! Main AIRA hun"
    reply_hi column optional — falls back to reply_en
    """
    entries = []
    if not os.path.exists(KB_CSV):
        return entries
    try:
        with open(KB_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw_kw   = row.get("keywords", "") or row.get("Keywords", "")
                reply_en = (row.get("reply_en","") or row.get("reply","") or row.get("Reply","")).strip()
                reply_hi = (row.get("reply_hi","") or reply_en).strip()
                if raw_kw and reply_en:
                    keywords = [k.strip().lower() for k in raw_kw.split(",") if k.strip()]
                    if keywords:
                        entries.append({"keywords": keywords, "reply_en": reply_en, "reply_hi": reply_hi})
    except Exception as e:
        print(f"⚠️  knowledge_base.csv load error: {e}")
    return entries


def _is_hindi(text: str) -> bool:
    """Check if message contains Hindi (Devanagari) characters"""
    return any('\u0900' <= ch <= '\u097F' for ch in text)


@app.route("/chat", methods=["POST"])
def chat():
    data    = request.get_json() or {}
    message = data.get("message", "")
    msg_lower = message.lower().strip()
    hindi   = _is_hindi(message)

    all_entries = _load_json_kb() + _load_csv_kb()
    matched = None
    for entry in all_entries:
        for keyword in entry["keywords"]:
            if keyword in msg_lower:
                matched = entry
                break
        if matched:
            break

    if matched:
        reply = matched["reply_hi"] if hindi else matched["reply_en"]
        return jsonify({"reply": reply, "no_answer": False})
    else:
        return jsonify({"reply": "", "no_answer": True})


# ── CHATBOT USER QUERY — Jab answer nahi mile to user query email karo ──
@app.route("/chat-query", methods=["POST"])
def chat_query():
    """
    User apna naam, email, mobile aur query submit karta hai.
    Admin ko poori details ke saath email aati hai.
    """
    d            = request.get_json() or {}
    user_name    = d.get("name",   "").strip()
    user_email   = d.get("email",  "").strip()
    user_mobile  = d.get("mobile", "").strip()
    user_query   = d.get("query",  "").strip()

    if not all([user_name, user_email, user_query]):
        return jsonify({"status": "error", "message": "Naam, email aur query zaroori hai ❌"})

    ADMIN_EMAIL = "praveennama7665@gmail.com"   # Admin ka email jahan query aayegi

    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = f"Solvex-AI Chatbot <{SMTP_EMAIL}>"
        msg["To"]      = ADMIN_EMAIL
        msg["Subject"] = f"🔔 Naya Chatbot Query — {user_name}"

        html_body = f"""
<html><body style="font-family:Arial,sans-serif;background:#f8fafc;padding:30px">
<div style="max-width:520px;margin:0 auto;background:white;border-radius:16px;padding:32px;border:1px solid #e2e8f0">
  <div style="background:linear-gradient(135deg,#1e3a8a,#2563eb);border-radius:12px;padding:20px;text-align:center;margin-bottom:24px">
    <h2 style="color:white;margin:0">🤖 Solvex-AI Chatbot</h2>
    <p style="color:rgba(255,255,255,.7);font-size:13px;margin-top:4px">Naya User Query Aaya Hai!</p>
  </div>

  <table style="width:100%;border-collapse:collapse;font-size:14px">
    <tr style="background:#f1f5f9">
      <td style="padding:12px 16px;font-weight:700;color:#374151;border-radius:8px 0 0 8px;width:35%">👤 Naam</td>
      <td style="padding:12px 16px;color:#0f172a">{user_name}</td>
    </tr>
    <tr>
      <td style="padding:12px 16px;font-weight:700;color:#374151">📧 Email</td>
      <td style="padding:12px 16px;color:#2563eb"><a href="mailto:{user_email}" style="color:#2563eb">{user_email}</a></td>
    </tr>
    <tr style="background:#f1f5f9">
      <td style="padding:12px 16px;font-weight:700;color:#374151">📞 Mobile</td>
      <td style="padding:12px 16px;color:#0f172a">{user_mobile if user_mobile else '—'}</td>
    </tr>
    <tr>
      <td style="padding:12px 16px;font-weight:700;color:#374151">⏰ Samay</td>
      <td style="padding:12px 16px;color:#64748b">{datetime.now().strftime('%d %b %Y, %I:%M %p')}</td>
    </tr>
  </table>

  <div style="margin-top:20px;background:#eff6ff;border-left:4px solid #2563eb;border-radius:8px;padding:16px">
    <p style="font-weight:700;color:#1e3a8a;margin:0 0 8px">💬 User Ka Sawaal:</p>
    <p style="color:#0f172a;font-size:15px;margin:0;line-height:1.6">{user_query}</p>
  </div>

  <div style="margin-top:24px;text-align:center">
    <a href="mailto:{user_email}?subject=Re: Aapka Solvex Query&body=Namaste {user_name},"
       style="background:linear-gradient(135deg,#1e3a8a,#2563eb);color:white;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:700;font-size:14px;display:inline-block">
      ✉️ User Ko Reply Karo
    </a>
  </div>

  <p style="color:#cbd5e1;font-size:11px;text-align:center;margin-top:20px">© Solvex-AI — Poornima University</p>
</div>
</body></html>"""

        text_body = f"""Naya Chatbot Query!

Naam:   {user_name}
Email:  {user_email}
Mobile: {user_mobile or '—'}
Samay:  {datetime.now().strftime('%d %b %Y, %I:%M %p')}

Sawaal:
{user_query}
"""
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, ADMIN_EMAIL, msg.as_string())

        return jsonify({"status": "success", "message": "✅ Aapka query submit ho gaya! Hum jald reply karenge."})

    except Exception as e:
        print(f"Chat Query Email Error: {e}")
        return jsonify({"status": "error", "message": "Query send nahi ho saki. Baad mein try karein 😔"})


# ── CHATBOT DATA RELOAD (optional admin endpoint) ──
@app.route("/admin/chatbot-reload", methods=["POST"])
def chatbot_reload():
    """
    POST /admin/chatbot-reload
    Files already har request pe fresh load hoti hain,
    yeh endpoint sirf confirm karta hai ki kitne entries loaded hain.
    """
    json_count = len(_load_json_kb())
    csv_count  = len(_load_csv_kb())
    return jsonify({
        "status": "success",
        "message": f"✅ Knowledge base ready: JSON={json_count} entries, CSV={csv_count} entries",
        "total": json_count + csv_count
    })


# ── START ──
if __name__ == "__main__":
    init_db()
    print("\n🚀 Solvex-AI server chal raha hai!")
    print("👉 Browser mein kholo: http://localhost:5000\n")
    print("🔐 Admin Secret Code: SOLVEX@ADMIN2025")
    app.run(debug=True, port=5000)