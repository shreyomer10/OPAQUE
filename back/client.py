# client_full.py
import base64
import hashlib
import hmac
import requests
from spake2 import SPAKE2_Symmetric

# --- Helper Functions ---
# These helper functions are used to handle data encoding and HMAC hashing,
# ensuring consistency between the client and server.

def b64e(b: bytes) -> str:
    """Encodes bytes to a base64 string."""
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    """Decodes a base64 string to bytes."""
    return base64.b64decode(s.encode())

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Calculates a SHA-256 HMAC of the data using the provided key."""
    return hmac.new(key, data, hashlib.sha256).digest()

# --- Configuration ---
# You would need to update these values for a real user
BASE = "http://127.0.0.1:8000"
username = "ayush"
password = b"ayush" # The password should be in bytes for the crypto functions

# --- Main Functions ---

def register_user():
    """
    Simulates the client-side registration process.
    It generates a verifier and sends it to the server with a salt.
    """
    print("=== REGISTER ===")
    # Generate a random salt for this user.
    # In production, this should be cryptographically secure and unique per user.
    salt = b"fixedsalt123456" 
    
    # Derive the verifier from the salt and password using a strong KDF (HMAC in this case).
    verifier = hmac_sha256(salt, password)

    # Prepare the request payload
    reg_req = {
        "username": username,
        "salt_b64": b64e(salt),
        "verifier_b64": b64e(verifier),
    }

    # Send the registration request to the server
    resp = requests.post(f"{BASE}/register", json=reg_req)
    resp_json = resp.json()
    print("[register] status:", resp.status_code, "resp:", resp_json)

    # Handle the case where the user already exists to allow the demo to proceed
    if not resp_json.get("ok"):
        print("[INFO] User already exists, skipping registration")


def login_user():
    """
    Simulates the two-step login process for the client.
    It performs the PAKE key exchange and authenticates the session.
    """
    # --- Step 1: Login Challenge ---
    print("\n=== LOGIN CHALLENGE ===")
    resp = requests.post(f"{BASE}/login/challenge", json={"username": username})
    resp.raise_for_status()
    ch = resp.json()
    if not ch.get("ok"):
        raise SystemExit("Challenge error: " + str(ch))

    # Retrieve the salt from the server's response
    salt = b64d(ch["salt_b64"])
    print("[DEBUG] Challenge salt (hex):", salt.hex())

    # Derive the verifier locally using the salt provided by the server.
    verifier_local = hmac_sha256(salt, password)
    print("[DEBUG] Local verifier (hex):", verifier_local.hex())

    # --- Step 2: Login Start ---
    # The client initializes SPAKE2 with its local verifier.
    client = SPAKE2_Symmetric(verifier_local, idSymmetric=b"pake-demo")
    msg_client = client.start()

    # Send the client's initial PAKE message to the server.
    r = requests.post(f"{BASE}/login/start", json={
        "username": username,
        "msg_client_b64": b64e(msg_client)
    })
    r.raise_for_status()
    resp = r.json()
    if not resp.get("ok"):
        raise SystemExit("login/start error: " + str(resp))

    session_id = resp["session_id"]
    msg_server = b64d(resp["msg_server_b64"])
    server_proof = b64d(resp["server_proof_b64"])

    # --- Step 3: Verify and Finalize ---
    # Client derives the shared session key using the server's message.
    session_key = client.finish(msg_server)
    print("[DEBUG] Session key (hex):", session_key.hex())

    # Verify the server's proof to ensure a man-in-the-middle attack hasn't occurred.
    expected_server_proof = hmac_sha256(session_key, b"server-proof")
    if not hmac.compare_digest(expected_server_proof, server_proof):
        raise SystemExit("Server proof invalid! Wrong password or MITM")
    print("Server proof OK ✅")

    # Send the client's final proof to finish the login process.
    client_proof = hmac_sha256(session_key, b"client-proof")
    r2 = requests.post(f"{BASE}/login/finish", json={
        "session_id": session_id,
        "client_proof_b64": b64e(client_proof)
    })
    r2.raise_for_status()
    print("[login/finish] status:", r2.status_code, "resp:", r2.text)

    # --- Step 4: Use the Protected Endpoint ---
    print("\n=== ACCESSING PROTECTED ENDPOINT ===")
    message_to_send = "Hello, world!"
    
    # Create an HMAC proof of the message using the shared session key.
    message_proof = hmac_sha256(session_key, message_to_send.encode('utf-8'))
    
    # Send the protected request
    protected_req = {
        "session_id": session_id,
        "message": message_to_send,
        "message_proof_b64": b64e(message_proof),
    }

    resp = requests.post(f"{BASE}/protected", json=protected_req)
    resp.raise_for_status()
    print("[protected] status:", resp.status_code, "resp:", resp.json())


if __name__ == "__main__":
    register_user()
    login_user()

