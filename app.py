from flask import Flask, jsonify, request
from flask_cors import CORS
import requests, json, time, hashlib, hmac, uuid

app = Flask(__name__)
CORS(app)  # ✅ allows ESP32 or any other client to access this API

CLIENT_ID = "najrfhsvekgj73g9wcer"
SECRET = "82141a89111044209040f5d45aeb5a65"
DEVICE_ID = "d737f25f789c4cb540sjye"
API_ENDPOINT = "https://openapi.tuyain.com"

TOKEN_CACHE = {"access_token": None, "expiry_time": 0}

def calculate_sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def generate_signature_for_token(client_id, t, nonce, string_to_sign, secret):
    s = client_id + t + nonce + string_to_sign
    return hmac.new(secret.encode(), s.encode(), hashlib.sha256).hexdigest().upper()

def generate_signature_for_business(client_id, access_token, t, nonce, string_to_sign, secret):
    s = client_id + access_token + t + nonce + string_to_sign
    return hmac.new(secret.encode(), s.encode(), hashlib.sha256).hexdigest().upper()

def build_string_to_sign(method, path, body="", signature_headers=""):
    body_hash = calculate_sha256(body)
    return f"{method}\n{body_hash}\n{signature_headers}\n{path}"

def get_access_token():
    method, path = "GET", "/v1.0/token?grant_type=1"
    t = str(int(time.time() * 1000))
    nonce = str(uuid.uuid4())
    string_to_sign = build_string_to_sign(method, path)
    sign = generate_signature_for_token(CLIENT_ID, t, nonce, string_to_sign, SECRET)

    headers = {
        "Content-Type": "application/json",
        "client_id": CLIENT_ID,
        "t": t,
        "nonce": nonce,
        "sign": sign,
        "sign_method": "HMAC-SHA256"
    }
    r = requests.get(API_ENDPOINT + path, headers=headers)
    data = r.json()
    if data.get("success"):
        access_token = data["result"]["access_token"]
        expire_time = data["result"]["expire_time"]
        TOKEN_CACHE["access_token"] = access_token
        TOKEN_CACHE["expiry_time"] = time.time() + expire_time - 60
        return access_token
    return None

def get_valid_token():
    if TOKEN_CACHE["access_token"] and time.time() < TOKEN_CACHE["expiry_time"]:
        return TOKEN_CACHE["access_token"]
    return get_access_token()

def control_device(state):
    access_token = get_valid_token()
    if not access_token:
        return {"success": False, "error": "Token error"}

    path = f"/v1.0/iot-03/devices/{DEVICE_ID}/commands"
    body = json.dumps({"commands": [{"code": "switch_1", "value": state}]})
    t = str(int(time.time() * 1000))
    nonce = str(uuid.uuid4())
    string_to_sign = build_string_to_sign("POST", path, body)
    sign = generate_signature_for_business(CLIENT_ID, access_token, t, nonce, string_to_sign, SECRET)

    headers = {
        "Content-Type": "application/json",
        "client_id": CLIENT_ID,
        "t": t,
        "nonce": nonce,
        "sign": sign,
        "sign_method": "HMAC-SHA256",
        "access_token": access_token
    }
    r = requests.post(API_ENDPOINT + path, data=body, headers=headers)
    return r.json()

@app.route('/control/<string:action>', methods=['POST'])
def api_control(action):
    if action not in ['on', 'off']:
        return jsonify({"success": False, "error": "Invalid action"}), 400
    state = True if action == 'on' else False
    result = control_device(state)
    return jsonify(result)

@app.route('/')
def home():
    return jsonify({"message": "Tuya Flask Controller is running and ready for ESP32."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
