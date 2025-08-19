
from pydantic import BaseModel
class RegisterRequest(BaseModel):
    username: str
    salt_b64: str
    verifier_b64: str

class ChallengeRequest(BaseModel):
    username: str

class LoginStartRequest(BaseModel):
    username: str
    msg_client_b64: str

class LoginFinishRequest(BaseModel):
    session_id: str
    client_proof_b64: str