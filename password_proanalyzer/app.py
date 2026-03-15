
from flask import Flask, render_template, request, jsonify
import re, math, hashlib, requests

app = Flask(__name__)

def calculate_charset(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): charset += 32
    return charset

def calculate_entropy(password):
    charset = calculate_charset(password)
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

def crack_time(entropy):
    guesses_per_second = 1e10
    guesses = 2 ** entropy
    seconds = guesses / guesses_per_second
    if seconds < 60:
        return f"{round(seconds)} Seconds"
    if seconds < 3600:
        return f"{round(seconds/60)} Minutes"
    if seconds < 86400:
        return f"{round(seconds/3600)} Hours"
    if seconds < 31536000:
        return f"{round(seconds/86400)} Days"
    return f"{round(seconds/31536000)} Years"

def password_strength(password):
    entropy = calculate_entropy(password)
    if entropy < 28:
        level, score = "Слабый", 1
    elif entropy < 36:
        level, score = "Средний", 2
    elif entropy < 60:
        level, score = "Сильный", 3
    else:
        level, score = "Очень сильный", 4
    return entropy, level, score

def check_password_leak(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200:
        return {"leaked": False, "count": 0}
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return {"leaked": True, "count": int(count)}
    return {"leaked": False, "count": 0}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    password = request.json["password"]
    entropy, level, score = password_strength(password)
    leak = check_password_leak(password)

    checks = {
        "length": len(password) >= 8,
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "number": bool(re.search(r"[0-9]", password)),
        "symbol": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }

    return jsonify({
        "entropy": entropy,
        "level": level,
        "score": score,
        "crack_time": crack_time(entropy),
        "checks": checks,
        "leaked": leak["leaked"],
        "count": leak["count"]
    })

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)