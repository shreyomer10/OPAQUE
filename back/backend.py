# main.py
from fastapi import FastAPI,Request
import os
from pydantic import BaseModel
import opaque
from dotenv import load_dotenv
load_dotenv()

app = FastAPI()

@app.get("/")
def home():
    return "Welcome to SPAKE @ AUTh"
# In a real app, the server's long-term private key and a user database would be managed
# in a more secure way. For this project, we'll keep it simple.
# You only need to run this ONCE to generate the key and store it securely.
# Let's assume you've already generated and stored it.
# server_sk = opaque.ServerSetup() 
# You can generate this and save it to a file. For our example, we will just use a predefined value.
SERVER_PRIVATE_KEY = os.getenv("SERVER_PRIVATE_KEY").encode('utf-8')
DATABASE = {}

class RegisterRequest(BaseModel):
    username: str
    client_request: str # We'll send this as a base64 encoded string
class FinalizeRegisterRequest(BaseModel):
    username: str
    client_record: str

@app.post("/register")
async def register_user(request: RegisterRequest):
    # This is the server's part of the registration
    # The server receives the client's request
    client_request_bytes = request.client_request.encode('utf-8')

    # The server responds with its part of the OPRF calculation
    server_response = opaque.create_registration_response(client_request_bytes, SERVER_PRIVATE_KEY)
    
    # Send the response back to the client
    return {"server_response": server_response.decode('utf-8')}


@app.post("/finalize-registration")
async def finalize_registration(request: FinalizeRegisterRequest):
    # This endpoint receives the final, client-generated verifier
    print(f"Finalizing registration for {request.username}")
    
    # In a real application, you would add validation and check for existing users
    
    DATABASE[request.username] = request.client_record
    
    print(f"Stored record for {request.username}: {DATABASE[request.username]}")
    
    return {"message": "Registration successful!", "username": request.username}