import requests

BASE_URL = "http://127.0.0.1:8000"

def test_verification():
    # 1. Login as Musa (Coordinator)
    print("Logging in as Musa...")
    resp = requests.post(f"{BASE_URL}/token", data={"username": "musa@works.ng", "password": "secret"})
    if resp.status_code != 200:
        print("Login Failed:", resp.text)
        return
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Logged in.")

    # 2. Get Reports
    resp = requests.get(f"{BASE_URL}/reports/", headers=headers)
    reports = resp.json()
    if not reports:
        print("No reports found.")
        return
    
    # 3. Find a report to verify
    # We need a report not created by Musa (who is likely ID 2). Assuming Demola (ID 1) created them.
    target_report = None
    for r in reports:
        if r["status"] == "unverified":
            target_report = r
            break
            
    if not target_report:
        print("No unverified reports found.")
        return

    print(f"Attempting to verify report: {target_report['title']} (ID: {target_report['id']})")

    # 4. Verify
    resp = requests.post(f"{BASE_URL}/reports/{target_report['id']}/verify", headers=headers)
    if resp.status_code == 200:
        print("Verification SUCCESS!")
        print("New Status:", resp.json()["status"])
        print("Verification Count:", resp.json()["verification_count"])
    else:
        print("Verification FAILED:", resp.status_code)
        print("Error:", resp.text)

if __name__ == "__main__":
    test_verification()
