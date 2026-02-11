import requests
import time

BASE_URL = "http://127.0.0.1:8000"

def test_backend():
    print(f"Testing connectivity to {BASE_URL}...")
    try:
        # 1. Health/Docs Check
        resp = requests.get(f"{BASE_URL}/docs")
        print(f"Docs endpoint status: {resp.status_code}")
        if resp.status_code != 200:
            print("FAILED: Backend seems down or returning error.")
            return

        # 2. Register User
        email = f"test_{int(time.time())}@example.com"
        password = "testpassword123"
        print(f"Attempting to register user: {email}")
        
        reg_resp = requests.post(f"{BASE_URL}/users/", json={
            "email": email,
            "password": password,
            "username": "testuser"
        })
        print(f"Registration response: {reg_resp.status_code} - {reg_resp.text}")
        
        if reg_resp.status_code != 200:
            print("Registration FAILED.")
            return

        # 3. Login (Get Token)
        print("Attempting to login...")
        login_resp = requests.post(f"{BASE_URL}/token", data={
            "username": email, # OAuth2 spec uses 'username' field
            "password": password
        })
        print(f"Login response: {login_resp.status_code} - {login_resp.text}")
        
        if login_resp.status_code == 403:
            print("SUCCESS: Login blocked as expected (Email not verified).")
        elif login_resp.status_code == 200:
             print("WARNING: Login succeeded but verification should be required?")
        else:
             print("Login FAILED or Unexpected.")
             
    except Exception as e:
        print(f"EXCEPTION: {e}")

if __name__ == "__main__":
    test_backend()
