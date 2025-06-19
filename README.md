# Certificate Authority 

A Certificate Authority system built with Python and Flask for issuing, revoking, and downloading X.509 certificates.

## Features

- Issue server certificates
- Revoke certificates
- Download issued certificates
- Logging and database-backed certificate storage

## Tools Used 

- Python, Flask
- SQLite + SQLAlchemy
- cryptography & pyOpenSSL
- Flask-Login

## Setup Instructions

```bash
git clone https://github.com/yourusername/Certificate_Authority_pydj.git
cd Certificate_Authority_py
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python ca_web.py
```

## How to run

- Run: python ca_web.py
- Go to : https://localhost:5000
  
# Enter Credentials:
- **Username:** `admin`
- **Password:** `admin123`
# Dashboard
- Issue Cert: Enter a site name and click `Issue Certificate` to generate a key, CSR, and signed certificate.
- View Cert: See a table of all issued certificates, including their serial number, subject, status, and issuance date.
- Download Cert: Click `Download` to download a certificate file.
- Revoke Cert: Click `Revoke` to mark a certificate as revoked, updated in the database.
- Logout: Click the `Logout` link to end the session.
