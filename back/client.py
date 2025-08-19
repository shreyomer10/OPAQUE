import requests
from opaque import CreateRegistrationRequest
import base64

# Configuration
SERVER_URL = "http://127.0.0.1:8000"
USERNAME = "shrey"
PASSWORD = "my_strong_password_123"

def register_user():
    # --- Round 1: Client sends blinded password to the server ---
    
    # 1. Client creates the initial OPRF request
    client_request_bytes = CreateRegistrationRequest(PASSWORD.encode('utf-8'))
    client_request_b64 = base64.b64encode(client_request_bytes).decode('utf-8')

    # 2. Client makes the API call to the server's /register endpoint
    print("Round 1: Client sending blinded message to server...")
    response = requests.post(
        f"{SERVER_URL}/register",
        json={"username": USERNAME, "client_request": client_request_b64}
    )
    
    server_response_b64 = response.json()["server_response"]
    
    # --- Round 2: Client uses server's response to create the final verifier ---
    
    # 3. Client finalizes the registration on its own side
    server_response_bytes = base64.b64decode(server_response_b64)
    client_record_bytes = opaque.finalize_registration_request(server_response_bytes)
    client_record_b64 = base64.b64encode(client_record_bytes).decode('utf-8')
    
    # 4. Client sends the final verifier to the server's /finalize-registration endpoint
    print("Round 2: Client sending final verifier to server...")
    final_response = requests.post(
        f"{SERVER_URL}/finalize-registration",
        json={"username": USERNAME, "client_record": client_record_b64}
    )

    print("--- Registration Process Complete ---")
    print("Server Response:", final_response.json())
    
# Run the registration process
if __name__ == "__main__":
    register_user()