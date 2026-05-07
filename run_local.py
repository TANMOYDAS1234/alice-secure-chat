import os
import time
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from Crypto.Cipher import AES

app = Flask(__name__)
CORS(app)

TRANSFER_DIR = "transfer"
NEW_MESSAGE = False

os.makedirs(TRANSFER_DIR, exist_ok=True)

@app.route("/")
def serve_ui():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, "ui", "Unified_Secure_Chat.html")
    with open(file_path, "r", encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    global NEW_MESSAGE
    data = request.get_json(force=True)
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"status": "ERROR", "message": "Empty message"}), 400

    secret_key = os.urandom(16)
    cipher = AES.new(secret_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    with open(f"{TRANSFER_DIR}/ciphertext.bin", "wb") as f: f.write(ciphertext)
    with open(f"{TRANSFER_DIR}/nonce.bin", "wb") as f: f.write(cipher.nonce)
    with open(f"{TRANSFER_DIR}/tag.bin", "wb") as f: f.write(tag)
    with open(f"{TRANSFER_DIR}/key.bin", "wb") as f: f.write(secret_key)

    NEW_MESSAGE = True

    return jsonify({"status": "SUCCESS", "trust": "0.95", "bit_error": "0.02"})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    global NEW_MESSAGE
    if not NEW_MESSAGE:
        return jsonify({"status": "EMPTY"})

    try:
        with open(f"{TRANSFER_DIR}/ciphertext.bin", "rb") as f: ciphertext = f.read()
        with open(f"{TRANSFER_DIR}/nonce.bin", "rb") as f: nonce = f.read()
        with open(f"{TRANSFER_DIR}/tag.bin", "rb") as f: f.read()
        with open(f"{TRANSFER_DIR}/key.bin", "rb") as f: secret_key = f.read()

        cipher = AES.new(secret_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        NEW_MESSAGE = False

        return jsonify({"status": "SUCCESS", "message": plaintext.decode()})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

if __name__ == "__main__":
    print("Local test server running on http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=True)
