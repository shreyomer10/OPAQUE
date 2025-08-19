# server.py
import os
import base64
import secrets
import hmac
import hashlib
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv
from pymongo import MongoClient
from spake2 import SPAKE2_Symmetric
from helper.converter import b64d,b64e,hmac_sha256
from models.models import RegisterRequest,ChallengeRequest,LoginFinishRequest,LoginStartRequest

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI is missing in .env")

mongo = MongoClient(MONGO_URI)
db = mongo["pake_demo"]
users = db["users"]         # { username, salt_b64, verifier_b64 }
sessions = db["sessions"]   # { session_id, key_b64, username }

# Indexes
users.create_index("username", unique=True)
sessions.create_index("session_id", unique=True)

# ---------- FastAPI ----------
app = FastAPI(title="SPAKE2 PAKE Demo with MongoDB")


@app.get("/")
def home():
    return {"ok": True, "message": "SPAKE2 PAKE demo (MongoDB) — password never sent during login."}

@app.post("/register")
def register(req: RegisterRequest):
    if users.find_one({"username": req.username}):
        return {"ok": False, "error": "User already exists"}

    # Validate base64
    try:
        _ = b64d(req.salt_b64)
        _ = b64d(req.verifier_b64)
    except Exception:
        return {"ok": False, "error": "Invalid base64 for salt/verifier"}

    users.insert_one({
        "username": req.username,
        "salt_b64": req.salt_b64,
        "verifier_b64": req.verifier_b64,
    })
    return {"ok": True, "message": "Registered"}

@app.post("/login/challenge")
def login_challenge(req: ChallengeRequest):
    user = users.find_one({"username": req.username})
    if not user:
        return {"ok": False, "error": "User not found"}
    return {"ok": True, "salt_b64": user["salt_b64"]}

@app.post("/login/start")
def login_start(req: LoginStartRequest):
    # debug
    print("LOGIN START request:", req)

    user = users.find_one({"username": req.username})
    if not user:
        return {"ok": False, "error": "User not found"}

    try:
        verifier = b64d(user["verifier_b64"])
    except Exception:
        return {"ok": False, "error": "Invalid verifier stored for user"}

    try:
        msg_client = b64d(req.msg_client_b64)
    except Exception:
        return {"ok": False, "error": "Invalid base64 for msg_client_b64"}

    # SPAKE2 server side (use same idSymmetric on both sides)
    server = SPAKE2_Symmetric(verifier, idSymmetric=b"pake-demo")
    msg_server = server.start()

    # derive the shared session key using client's message
    try:
        session_key = server.finish(msg_client)
    except Exception as e:
        return {"ok": False, "error": f"SPAKE2 finish failed: {e}"}

    if not isinstance(session_key, (bytes, bytearray)):
        session_key = bytes(session_key)

    server_proof = hmac_sha256(session_key, b"server-proof")

    # Persist only the session key (base64). No pickling of internal object.
    session_id = secrets.token_hex(16)
    sessions.insert_one({
        "session_id": session_id,
        "username": req.username,
        "key_b64": b64e(session_key)
    })
    print("[DEBUG] login_start for user:", req.username)
    print("[DEBUG] verifier (hex):", verifier.hex())
    print("[DEBUG] msg_client_b64:", req.msg_client_b64)
    print("[DEBUG] msg_server (b64):", b64e(msg_server))
    print("[DEBUG] session_key (hex):", session_key.hex())
    print("[DEBUG] server_proof (hex):", server_proof.hex())


    return {
        "ok": True,
        "session_id": session_id,
        "msg_server_b64": b64e(msg_server),
        "server_proof_b64": b64e(server_proof),
    }

@app.post("/login/finish")
def login_finish(req: LoginFinishRequest):
    sess = sessions.find_one({"session_id": req.session_id})
    if not sess:
        return {"ok": False, "error": "Invalid session"}

    try:
        key = b64d(sess["key_b64"])
    except Exception:
        sessions.delete_one({"session_id": req.session_id})
        return {"ok": False, "error": "Corrupt session key"}

    expected = hmac_sha256(key, b"client-proof")
    try:
        client_proof = b64d(req.client_proof_b64)
    except Exception:
        sessions.delete_one({"session_id": req.session_id})
        return {"ok": False, "error": "Invalid base64 for client_proof_b64"}

    # Constant-time compare
    if not hmac.compare_digest(expected, client_proof):
        sessions.delete_one({"session_id": req.session_id})
        return {"ok": False, "error": "Bad client proof"}

    # Success — both sides share the same key derived from correct password
    sessions.delete_one({"session_id": req.session_id})
    
    
    
    
    print("[DEBUG] login_finish for session:", req.session_id)
    print("[DEBUG] loaded key (hex):", key.hex())
    print("[DEBUG] expected client_proof (hex):", expected.hex())
    print("[DEBUG] received client_proof (b64):", req.client_proof_b64)
    print("[DEBUG] received client_proof (hex):", client_proof.hex())

    return {"ok": True, "message": "Login successful"}
