# WatchWay Backend

The official backend API for **WatchWay Nigeria**, a platform for tracking infrastructure decay. Built with **FastAPI** and **SQLite**.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/HectorGitt/watchway-backend.git
    cd watchway-backend
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Environment Setup:**
    Create a `.env` file in the root directory with the following variables:
    ```env
    DATABASE_URL=postgresql://user:password@localhost:5432/watchway
    SECRET_KEY=your_secret_key_here
    MAIL_USERNAME=your_email@gmail.com
    MAIL_PASSWORD=your_app_password
    MAIL_FROM=noreply@watchway.ng
    MAIL_PORT=587
    MAIL_SERVER=smtp.gmail.com
    ```

5.  **Initialize Database & Seed Data:**
    ```bash
    python seed_db.py
    ```
    This script connects to the PostgreSQL database defined in `.env`, creates tables, and populates it with:
    -   **Admin User**: `admin@watchway.ng` / `adminsecret`
    -   **Coordinator**: `musa@works.ng` / `secret`
    -   **Citizen**: `demo@watchway.ng` / `secret`
    -   Sample Hazard Reports

### Running the Server

Start the development server with live reload:

```bash
uvicorn main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

## 📚 API Documentation

Access the interactive API docs (Swagger UI) at:
**[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

## 🛠️ Tech Stack

-   **Framework**: FastAPI
-   **Database**: PostgreSQL (via SQLAlchemy ORM)
-   **Authentication**: OAuth2 with JWT (JSON Web Tokens)
-   **Email**: FastAPI-Mail (SMTP)

## 🔑 Key Features

-   **User Management**: Registration, Login, and Role-based access (Citizen, Coordinator, Admin).
-   **Reporting**: Submit infrastructure hazards with location and images.
-   **Verification**: "Trust Protocol" mechanism to verify reports.
-   **Jurisdiction Logic**: Auto-tagging reports as Federal or State.
-   **Admin Dashboard**: Endpoints for managing users and roles.
