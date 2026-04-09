import os
import requests
from flask import Flask, redirect, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Environment Variables (set these in Render)
CLIENT_ID = os.environ.get("BOX_CLIENT_ID")
CLIENT_SECRET = os.environ.get("BOX_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("BOX_REDIRECT_URI")

# Step 1: Redirect user to Box login
@app.route("/")
def home():
    auth_url = (
        "https://account.box.com/api/oauth2/authorize"
        f"?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
    )
    return f'<a href="{auth_url}">Login with Box</a>'


# Step 2: Handle callback from Box
@app.route("/callback")
def callback():
    code = request.args.get("code")

    if not code:
        return "No authorization code received", 400

    # Exchange code for access token
    token_url = "https://api.box.com/oauth2/token"

    response = requests.post(token_url, data={
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI
    })

    data = response.json()

    if "access_token" not in data:
        return jsonify({"error": data}), 400

    return jsonify({
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token")
    })


# Optional: Health check
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
