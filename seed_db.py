from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
import secrets
from datetime import datetime
import auth # Import auth to access hashing function

# Ensure tables exist
models.Base.metadata.create_all(bind=engine)

def seed_data():
    db = SessionLocal()

    # Check if we already have reports
    if db.query(models.Report).count() > 0:
        print("Database already has data.")
        return

    # Create a mock user if needed
    user = db.query(models.User).filter(models.User.email == "demo@watchway.ng").first()
    if not user:
        user = models.User(
            username="Demola",
            email="demo@watchway.ng",
            hashed_password=auth.get_password_hash("secret"), # Properly hashed
            is_verified=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    print(f"Seeding data for user: {user.username}...")

    # Create Coordinator
    coord = db.query(models.User).filter(models.User.email == "musa@works.ng").first()
    if not coord:
        coord = models.User(
            username="Engr. Musa",
            email="musa@works.ng",
            hashed_password=auth.get_password_hash("secret"), # Properly hashed
            role="coordinator",
            state_assigned="Lagos",
            is_verified=True
        )
        db.add(coord)
        db.commit()
        print("Created Coordinator: Engr. Musa (Lagos)")

    # Create Admin
    admin = db.query(models.User).filter(models.User.email == "admin@watchway.ng").first()
    if not admin:
        admin = models.User(
            username="Admin User",
            email="admin@watchway.ng",
            hashed_password=auth.get_password_hash("adminsecret"),
            role="admin",
            is_verified=True
        )
        db.add(admin)
        db.commit()
        print("Created Admin: Admin User")

    reports = [
        models.Report(
            id=secrets.token_hex(4),
            title="Massive Crater on Ikorodu Road",
            description="Deep pothole causing heavy traffic near the Fadeyi Bus Stop. Several cars have damaged their suspensions here.",
            lat=6.5432,
            lng=3.3765,
            address="Ikorodu Rd, Fadeyi, Lagos",
            state="Lagos",
            jurisdiction="FEDERAL",
            status="verified",
            severity_level=9,
            live_image_url="https://images.unsplash.com/photo-1515162816999-a0c47dc192f7?auto=format&fit=crop&q=80&w=2000",
            reporter_id=user.id,
            created_at=datetime.utcnow()
        ),
        models.Report(
            id=secrets.token_hex(4),
            title="Collapsed Street Light",
            description="Street light pole fell during the storm last night. It is blocking one lane of the street.",
            lat=9.0765,
            lng=7.3986,
            address="Adetokunbo Ademola Cres, Wuse 2, Abuja",
            state="Abuja",
            jurisdiction="STATE",
            status="unverified",
            severity_level=6,
            live_image_url="https://plus.unsplash.com/premium_photo-1664303847960-586318f59035?q=80&w=1974&auto=format&fit=crop",
            reporter_id=user.id,
            created_at=datetime.utcnow()
        ),
        models.Report(
            id=secrets.token_hex(4),
            title="Flooded Underbridge",
            description="Drainage is completely blocked. The road is impassable whenever it rains.",
            lat=6.4521,
            lng=3.4102,
            address="Ozumba Mbadiwe Ave, Victoria Island, Lagos",
            state="Lagos",
            jurisdiction="STATE",
            status="fixed",
            severity_level=8,
            live_image_url="https://images.unsplash.com/photo-1585579331818-f257a44c9b36?auto=format&fit=crop&q=80&w=2000",
            reporter_id=user.id,
            created_at=datetime.utcnow()
        )
    ]

    for report in reports:
        db.add(report)
        print(f"Added: {report.title} ({report.id})")

    db.commit()
    print("Seeding Complete!")
    db.close()

if __name__ == "__main__":
    seed_data()
