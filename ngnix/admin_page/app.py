from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify
import requests
import urllib3
import secrets
import logging
import time
import os
import socket
import csv
import sys
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent.futures import ThreadPoolExecutor

NLP_BASE_DIR = r"C:\ngnix\nginx-1.29.7\llm"
if NLP_BASE_DIR not in sys.path:
    sys.path.insert(0, NLP_BASE_DIR)
from nlp_engine import classify_intent, generate_response, load_traffic_data

app = Flask(__name__)

# =========================
# 기본 설정
# =========================
app.secret_key = "change-this-secret-key"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False   # HTTPS로 관리자 페이지 운영하면 True로 변경
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# 환경별 수정 필요
# =========================
ADMIN_ID = "admin"
ADMIN_PW_HASH = generate_password_hash("1234")

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

LB_LOG_FILE = r"C:\ngnix\nginx-1.29.7\logs\lb_access.log"

MONITOR_TARGETS = [
    {"name": "Web1-HTTP", "host": "192.168.37.134", "port": 80, "mode": "http", "url": "http://192.168.37.134:80"},
    {"name": "Web2-HTTP", "host": "192.168.37.133", "port": 80, "mode": "http", "url": "http://192.168.37.133:80"},
]

MAX_LOGIN_FAILS = 5
LOCK_TIME_SECONDS = 600

executor = ThreadPoolExecutor(max_workers=len(MONITOR_TARGETS))
login_fail_data = {}

# =========================
# 관리자 보안 로그
# =========================
admin_logger = logging.getLogger("admin_security")
admin_logger.setLevel(logging.INFO)

if not admin_logger.handlers:
    handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "admin_security.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8"
    )
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(formatter)
    admin_logger.addHandler(handler)

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

def write_admin_log(event, user_id="-"):
    ip = get_client_ip()
    admin_logger.info(f"{event} | ip={ip} | user={user_id}")

# =========================
# 보안 헤더
# =========================
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self';"
    return response

# =========================
# 날짜별 CSV 자동 저장
# =========================
def get_daily_log_file():
    return os.path.join(LOG_DIR, f"monitor_logs_{datetime.now().strftime('%Y-%m-%d')}.csv")

def save_monitor_log(data_row):
    log_file = get_daily_log_file()
    file_exists = os.path.isfile(log_file)
    try:
        with open(log_file, mode="a", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Time", "Target", "URL", "Mode", "Status", "Latency(ms)"])
            writer.writerow(data_row)
    except Exception:
        pass

# =========================
# 상태 체크
# =========================
def check_http_target(url):
    start = time.time()
    try:
        r = requests.get(url, timeout=2, verify=False)
        ms = int((time.time() - start) * 1000)
        return f"정상 ({r.status_code})", ms
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        return f"다운 / 오류: {e}", ms

def check_tcp_target(host, port):
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=2):
            ms = int((time.time() - start) * 1000)
            return "정상 (TCP 연결 성공)", ms
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        return f"다운 / 오류: {e}", ms

def check_task(target):
    if target["mode"] in ["http", "https"]:
        status, ms = check_http_target(target["url"])
    else:
        status, ms = check_tcp_target(target["host"], target["port"])

    save_monitor_log([
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target["name"],
        target["url"],
        target["mode"].upper(),
        status,
        ms
    ])

    return {
        "name": target["name"],
        "url": target["url"],
        "mode": target["mode"].upper(),
        "status": status,
        "response_time": ms
    }

# =========================
# 로그 읽기
# =========================
def read_recent_admin_logs(limit=10):
    log_file = os.path.join(LOG_DIR, "admin_security.log")
    if not os.path.exists(log_file):
        return []

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [line.strip() for line in lines[-limit:]][::-1]
    except Exception as e:
        return [f"로그 읽기 오류: {e}"]

def read_recent_lb_logs(limit=10):
    if not os.path.exists(LB_LOG_FILE):
        return []

    try:
        with open(LB_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [line.strip() for line in lines[-limit:]][::-1]
    except Exception as e:
        return [f"LB 로그 읽기 오류: {e}"]

# =========================
# HTML
# =========================
LOGIN_HTML = """
<html>
<head>
    <meta charset="utf-8">
    <title>Admin Login</title>
    <style>
        body {
            background:#121212;
            color:white;
            font-family:sans-serif;
            display:flex;
            justify-content:center;
            align-items:center;
            height:100vh;
            margin:0;
        }
        .box {
            width:340px;
            background:#1e1e1e;
            padding:36px;
            border-radius:16px;
            border:1px solid #333;
            box-shadow:0 10px 30px rgba(0,0,0,0.45);
        }
        h2 {
            margin-top:0;
            margin-bottom:24px;
            text-align:center;
        }
        input {
            width:100%;
            padding:12px;
            margin-bottom:14px;
            box-sizing:border-box;
            background:#222;
            color:white;
            border:1px solid #444;
            border-radius:8px;
        }
        button {
            width:100%;
            padding:12px;
            background:#2563eb;
            color:white;
            border:none;
            border-radius:8px;
            font-weight:bold;
            cursor:pointer;
        }
        .error {
            color:#ff5c5c;
            font-size:13px;
            text-align:center;
            margin-top:14px;
        }
        .small {
            color:#888;
            font-size:12px;
            text-align:center;
            margin-top:10px;
        }
    </style>
</head>
<body>
    <div class="box">
        <h2>관리자 로그인</h2>
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="text" name="username" placeholder="ID">
            <input type="password" name="password" placeholder="PW">
            <button type="submit">LOGIN</button>
        </form>
        <p class="error">{{ error }}</p>
        <p class="small">CSRF / 세션 보안 / 로그인 실패 제한 적용</p>
    </div>
</body>
</html>
"""

HOME_HTML = """
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="5">
    <title>보안 관제 대시보드</title>
    <style>
        body {
            background:#121212;
            color:#eee;
            font-family:sans-serif;
            padding:20px;
            margin:0;
        }
        .container {
            max-width:1400px;
            margin:auto;
        }
        .header {
            display:flex;
            justify-content:space-between;
            align-items:center;
            border-bottom:1px solid #333;
            padding-bottom:15px;
            margin-bottom:20px;
        }
        .badge {
            display:inline-block;
            padding:5px 12px;
            background:#262626;
            border:1px solid #444;
            border-radius:20px;
            font-size:12px;
            margin-right:8px;
            margin-bottom:8px;
            color:#bbb;
        }
        .grid {
            display:grid;
            grid-template-columns:repeat(2, minmax(320px, 1fr));
            gap:18px;
        }
        .card {
            background:#1b1b1b;
            border:1px solid #2d2d2d;
            padding:20px;
            border-radius:12px;
        }
        table {
            width:100%;
            border-collapse:collapse;
            margin-top:15px;
        }
        th, td {
            padding:12px;
            border-bottom:1px solid #333;
            text-align:left;
            vertical-align:top;
        }
        .ok { color:#00d26a; font-weight:bold; }
        .err { color:#ff5c5c; font-weight:bold; }
        .mono { font-family:monospace; color:#aaa; }
        ul { padding-left:18px; }
        li { margin-bottom:8px; word-break:break-all; }
        .small { color:#777; font-size:12px; margin-top:10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ 보안 관제 대시보드</h1>
            <div style="display:flex; align-items:center; gap:10px;">
                <a href="/chat" style="display:inline-flex; align-items:center; gap:6px; color:#58a6ff; text-decoration:none; border:1px solid #30363d; background:#0d1117; padding:6px 14px; border-radius:6px; font-size:13px; font-weight:bold;">
                    <span style="width:6px; height:6px; background:#3fb950; border-radius:50%; box-shadow:0 0 5px #3fb950; display:inline-block;"></span>
                    트래픽 분석 AI
                </a>
                <a href="/logout" style="color:#aaa; text-decoration:none; border:1px solid #444; padding:6px 14px; border-radius:6px;">로그아웃</a>
            </div>
        </div>

        <div style="margin-bottom:14px; color:#888; font-size:13px;">
            5초 자동 새로고침 / 현재 접속 IP: {{ client_ip }} / 로그인 사용자: {{ admin_id }}
        </div>

        <div style="margin-bottom:20px;">
            <span class="badge">비밀번호 해시 검증</span>
            <span class="badge">CSRF 방어</span>
            <span class="badge">로그인 실패 5회 제한</span>
            <span class="badge">보안 쿠키</span>
            <span class="badge">보안 헤더</span>
            <span class="badge">관리자 보안 로그</span>
            <span class="badge">LB 로그 조회</span>
            <span class="badge">날짜별 CSV 자동 저장</span>
            <span class="badge">병렬 상태 체크</span>
        </div>

        <div class="grid">
            <div class="card" style="grid-column:1 / span 2;">
                <h2>관제 대상 상태</h2>
                <table>
                    <tr>
                        <th>대상</th>
                        <th>엔드포인트</th>
                        <th>방식</th>
                        <th>응답시간</th>
                        <th>현재 상태</th>
                    </tr>
                    {% for r in monitor_results %}
                    <tr>
                        <td><b>{{ r.name }}</b></td>
                        <td class="mono">{{ r.url }}</td>
                        <td>{{ r.mode }}</td>
                        <td>{{ r.response_time }} ms</td>
                        <td class="{{ 'ok' if '정상' in r.status else 'err' }}">{{ r.status }}</td>
                    </tr>
                    {% endfor %}
                </table>
                <p class="small">HTTP/HTTPS는 웹 요청, SSH/DB는 TCP 연결 기준으로 확인</p>
            </div>

            <div class="card">
                <h2>세션 보호 상태</h2>
                <ul>
                    <li>HttpOnly : {{ session_cookie_httponly }}</li>
                    <li>Secure : {{ session_cookie_secure }}</li>
                    <li>SameSite : {{ session_cookie_samesite }}</li>
                    <li>세션 만료 시간 : {{ session_lifetime_minutes }}분</li>
                </ul>
            </div>

            <div class="card">
                <h2>로그인 보호 정책</h2>
                <ul>
                    <li>최대 로그인 실패 횟수 : {{ max_login_fails }}회</li>
                    <li>잠금 시간 : {{ lock_time_minutes }}분</li>
                    <li>관리자 보안 로그 : logs/admin_security.log</li>
                    <li>관제 CSV 로그 : logs/monitor_logs_날짜.csv</li>
                </ul>
            </div>

            <div class="card">
                <h2>최근 관리자 보안 로그</h2>
                <ul>
                    {% for log in recent_admin_logs %}
                    <li>{{ log }}</li>
                    {% endfor %}
                </ul>
            </div>

            <div class="card">
                <h2>최근 LB 접속 로그</h2>
                <ul>
                    {% for log in recent_lb_logs %}
                    <li>{{ log }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
"""

# =========================
# 라우트
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    client_ip = get_client_ip()
    now = time.time()

    if client_ip not in login_fail_data:
        login_fail_data[client_ip] = {"fail_count": 0, "lock_until": 0}

    if request.method == "GET":
        session["csrf_token"] = secrets.token_hex(16)

    if login_fail_data[client_ip]["lock_until"] > now:
        remain = int(login_fail_data[client_ip]["lock_until"] - now)
        error = f"로그인 실패가 너무 많아 {remain}초 후 다시 시도하세요."
        return render_template_string(
            LOGIN_HTML,
            error=error,
            csrf_token=session.get("csrf_token", "")
        )

    if request.method == "POST":
        form_csrf_token = request.form.get("csrf_token", "")
        session_csrf_token = session.get("csrf_token", "")

        if not form_csrf_token or form_csrf_token != session_csrf_token:
            write_admin_log("CSRF_BLOCKED", "-")
            error = "잘못된 요청입니다."
            session["csrf_token"] = secrets.token_hex(16)
            return render_template_string(
                LOGIN_HTML,
                error=error,
                csrf_token=session.get("csrf_token", "")
            )

        user_id = request.form.get("username")
        user_pw = request.form.get("password")

        if user_id == ADMIN_ID and check_password_hash(ADMIN_PW_HASH, user_pw):
            session.permanent = True
            session["logged_in"] = True
            session["admin_id"] = user_id
            session["csrf_token"] = secrets.token_hex(16)

            login_fail_data[client_ip]["fail_count"] = 0
            login_fail_data[client_ip]["lock_until"] = 0

            write_admin_log("LOGIN_SUCCESS", user_id)
            return redirect(url_for("home"))
        else:
            login_fail_data[client_ip]["fail_count"] += 1
            write_admin_log("LOGIN_FAIL", user_id if user_id else "-")
            session["csrf_token"] = secrets.token_hex(16)

            if login_fail_data[client_ip]["fail_count"] >= MAX_LOGIN_FAILS:
                login_fail_data[client_ip]["lock_until"] = now + LOCK_TIME_SECONDS
                error = "로그인 5회 실패로 10분간 로그인할 수 없습니다."
            else:
                remain_count = MAX_LOGIN_FAILS - login_fail_data[client_ip]["fail_count"]
                error = f"아이디 또는 비밀번호가 틀렸습니다. 남은 시도 횟수: {remain_count}"

    return render_template_string(
        LOGIN_HTML,
        error=error,
        csrf_token=session.get("csrf_token", "")
    )

@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    monitor_results = list(executor.map(check_task, MONITOR_TARGETS))
    recent_admin_logs = read_recent_admin_logs(10)
    recent_lb_logs = read_recent_lb_logs(10)

    session_lifetime_minutes = int(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() / 60)
    lock_time_minutes = int(LOCK_TIME_SECONDS / 60)

    return render_template_string(
        HOME_HTML,
        monitor_results=monitor_results,
        client_ip=get_client_ip(),
        admin_id=session.get("admin_id", "-"),
        session_cookie_httponly=app.config["SESSION_COOKIE_HTTPONLY"],
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_samesite=app.config["SESSION_COOKIE_SAMESITE"],
        session_lifetime_minutes=session_lifetime_minutes,
        max_login_fails=MAX_LOGIN_FAILS,
        lock_time_minutes=lock_time_minutes,
        recent_admin_logs=recent_admin_logs,
        recent_lb_logs=recent_lb_logs
    )


# =========================
# 트래픽 분석 AI 챗봇
# =========================
CHAT_HTML_PATH = r"C:\ngnix\nginx-1.29.7\llm\chat.html"

@app.route("/chat")
def chat():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    if os.path.exists(CHAT_HTML_PATH):
        return open(CHAT_HTML_PATH, encoding="utf-8").read()
    return "<h1>chat.html 파일을 찾을 수 없습니다. 경로: " + CHAT_HTML_PATH + "</h1>"


@app.route("/api/traffic-data")
def api_traffic_data():
    if not session.get("logged_in"):
        return jsonify({"error": "로그인 필요"}), 401
    try:
        import pandas as pd
        csv_path = r"C:\ngnix\nginx-1.29.7\logs\processed_data.csv"
        df = pd.read_csv(csv_path)

        # 이상 탐지
        thr = df["avg_response_time"].mean() + 2 * df["avg_response_time"].std()
        df["is_anomaly"] = ((df["error_rate"] > 0) | (df["avg_response_time"] > thr)).astype(int)

        normal  = int((df["is_anomaly"] == 0).sum())
        danger  = int((df["avg_response_time"] > thr).sum())
        caution = int((df["error_rate"] > 0).sum()) - danger
        caution = max(0, caution)

        records = []
        for _, r in df.iterrows():
            records.append({
                "time":     r["time"],
                "server":   r["server"],
                "real_req": int(r["request_count"]),
                "real_rt":  round(float(r["avg_response_time"]), 2),
                "real_err": f"{round(float(r['error_rate'])*100, 1)}%",
                "real_succ":f"{round(float(r['success_rate'])*100, 1)}%",
                "anomaly":  f"{round(float(r['is_anomaly'])*100, 1)}%",
                "risk":     "🔴 위험" if r["avg_response_time"] > thr
                            else ("🟡 주의" if r["error_rate"] > 0 else "🟢 정상")
            })

        return jsonify({
            "summary": {
                "total":       len(df),
                "normal":      normal,
                "caution":     caution,
                "danger":      danger,
                "avg_request": round(float(df["request_count"].mean()), 2),
                "avg_rt":      round(float(df["avg_response_time"].mean()), 2),
                "servers":     df["server"].unique().tolist()
            },
            "records": records
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/chat", methods=["POST"])
def api_chat():
    if not session.get("logged_in"):
        return jsonify({"error": "로그인 필요"}), 401
    user_text = request.json.get("message", "").strip()
    if not user_text:
        return jsonify({"reply": "질문을 입력해주세요."})
    data   = load_traffic_data()
    intent = classify_intent(user_text)
    reply  = generate_response(intent, data)
    return jsonify({"reply": reply, "intent": intent})

@app.route("/logout")
def logout():
    if session.get("logged_in"):
        write_admin_log("LOGOUT", session.get("admin_id", "-"))
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)