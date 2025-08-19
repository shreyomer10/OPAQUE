# client_full.py
import base64
import hashlib
import hmac
import requests
from spake2 import SPAKE2_Symmetric

# Helpers
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

BASE = "http://127.0.0.1:8000"

# User credentials
username = "alice"
password = b"shrey"

# === REGISTER ===
print("=== REGISTER ===")
# For demo: generate random salt for registration
salt = b"fixedsalt123456"  # replace with os.urandom(16) in production
verifier = hmac_sha256(salt, password)

reg_req = {
    "username": username,
    "salt_b64": b64e(salt),
    "verifier_b64": b64e(verifier),
}

resp = requests.post(f"{BASE}/register", json=reg_req)
resp_json = resp.json()
print("[register] status:", resp.status_code, "resp:", resp_json)

# If user already exists, just proceed to login
if not resp_json.get("ok"):
    print("[INFO] User already exists, skipping registration")

# === LOGIN CHALLENGE ===
print("\n=== LOGIN CHALLENGE ===")
resp = requests.post(f"{BASE}/login/challenge", json={"username": username})
ch = resp.json()
if not ch.get("ok"):
    raise SystemExit("Challenge error: " + str(ch))

salt = b64d(ch["salt_b64"])
print("[DEBUG] Challenge salt (hex):", salt.hex())

# derive verifier using server-provided salt
verifier_local = hmac_sha256(salt, password)
print("[DEBUG] Local verifier (hex):", verifier_local.hex())

# === LOGIN START ===
client = SPAKE2_Symmetric(verifier_local, idSymmetric=b"pake-demo")
msg_client = client.start()

r = requests.post(f"{BASE}/login/start", json={
    "username": username,
    "msg_client_b64": b64e(msg_client)
})
resp = r.json()
if not resp.get("ok"):
    raise SystemExit("login/start error: " + str(resp))

session_id = resp["session_id"]
msg_server = b64d(resp["msg_server_b64"])
server_proof = b64d(resp["server_proof_b64"])
print("[DEBUG] Server msg (hex):", msg_server.hex())
print("[DEBUG] Server proof (hex):", server_proof.hex())

# === FINISH CLIENT SIDE ===
session_key = client.finish(msg_server)
print("[DEBUG] Session key (hex):", session_key.hex())

expected_server_proof = hmac_sha256(session_key, b"server-proof")
if not hmac.compare_digest(expected_server_proof, server_proof):
    raise SystemExit("Server proof invalid! Wrong password or MITM")
print("Server proof OK ✅")

client_proof = hmac_sha256(session_key, b"client-proof")
r2 = requests.post(f"{BASE}/login/finish", json={
    "session_id": session_id,
    "client_proof_b64": b64e(client_proof)
})
print("[login/finish] status:", r2.status_code, "resp:", r2.text)
