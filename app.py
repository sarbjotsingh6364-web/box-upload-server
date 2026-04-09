import os
import time
import requests
from flask import Flask, jsonify
from flask_cors import CORS
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import uuid

app = Flask(__name__)
CORS(app)

# Environment Variables
CLIENT_ID = os.environ.get("BOX_CLIENT_ID")
CLIENT_SECRET = os.environ.get("BOX_CLIENT_SECRET")
PUBLIC_KEY_ID = os.environ.get("BOX_PUBLIC_KEY_ID")
PRIVATE_KEY = os.environ.get("BOX_PRIVATE_KEY", "").replace("\\n", "\n")
PASSPHRASE = os.environ.get("BOX_PASSPHRASE")
ENTERPRISE_ID = os.environ.get("BOX_ENTERPRISE_ID")
FOLDER_ID = os.environ.get("BOX_FOLDER_ID", "375842438354")

# Token Cache
_token_cache = {"token": None, "expires_at": 0}


# ✅ Home Route (Fix 404 issue)
@app.route("/")
def home():
    return "Box Upload Server is running 🚀"


# ✅ Health Check
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# 🔐 Get Access Token
def get_access_token():
    now = time.time()

    # Return cached token if valid
    if _token_cache["token"] and now < _token_cache["expires_at"] - 60:
        return _token_cache["token"]

    # Validate required env variables
    required_vars = {
        "BOX_CLIENT_ID": CLIENT_ID,
        "BOX_CLIENT_SECRET": CLIENT_SECRET,
        "BOX_PUBLIC_KEY_ID": PUBLIC_KEY_ID,
        "BOX_PRIVATE_KEY": PRIVATE_KEY,
        "BOX_ENTERPRISE_ID": ENTERPRISE_ID
    }

    for key, value in required_vars.items():
        if not value:
            raise Exception(f"Missing environment variable: {key}")

    # Load private key
    private_key_bytes = PRIVATE_KEY.encode("utf-8")
    passphrase_bytes = PASSPHRASE.encode("utf-8") if PASSPHRASE else None

    key = load_pem_private_key(
        private_key_bytes,
        password=passphrase_bytes,
        backend=default_backend()
    )

    # Create JWT assertion
    claims = {
        "iss": CLIENT_ID,
        "sub": ENTERPRISE_ID,
        "box_sub_type": "enterprise",
        "aud": "https://api.box.com/oauth2/token",
        "jti": str(uuid.uuid4()),
        "exp": int(now) + 45
    }

    assertion = jwt.encode(
        claims,
        key,
        algorithm="RS256",
        headers={"kid": PUBLIC_KEY_ID}
    )

    # Request access token from Box
    resp = requests.post(
        "https://api.box.com/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        }
    )

    # ✅ Better error handling
    if resp.status_code != 200:
        raise Exception(f"Box API error: {resp.text}")

    data = resp.json()
    token = data.get("access_token")
    expires_in = data.get("expires_in", 3600)

    # Cache token
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + expires_in

    return token


# 🔑 Token API
@app.route("/token", methods=["GET"])
def token():
    try:
        t = get_access_token()
        return jsonify({
            "access_token": t,
            "folder_id": FOLDER_ID
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Run locally (Render uses gunicorn)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
