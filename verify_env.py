from dotenv import load_dotenv
import os

# Force reload to be sure
load_dotenv()

required_keys = [
    "MAIL_USERNAME",
    "MAIL_PASSWORD",
    "MAIL_FROM",
    "MAIL_PORT",
    "MAIL_SERVER"
]

print("--- Checking Environment Variables ---")
all_present = True
for key in required_keys:
    value = os.getenv(key)
    if value:
        masked = value
        if "PASSWORD" in key and len(value) > 3:
            masked = value[:2] + "****" + value[-1]
        print(f"✅ {key}: Found ({masked})")
    else:
        print(f"❌ {key}: MISSING")
        all_present = False

if all_present:
    print("\nSUCCESS: All email variables are loaded.")
else:
    print("\nFAILURE: Some variables are missing.")
