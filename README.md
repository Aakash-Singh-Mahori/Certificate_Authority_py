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
