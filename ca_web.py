from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    PrivateFormat, BestAvailableEncryption, Encoding, NoEncryption, load_pem_private_key
)
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import os
import logging
from OpenSSL import crypto

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ca.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup logging
logging.basicConfig(filename='ca.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize database
db = SQLAlchemy(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database model for issued certificates
class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(50), unique=True, nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='active')  # active or revoked
    cert_path = db.Column(db.String(200), nullable=False)
    issued_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# CA class to manage certificate operations
class CertificateAuthority:
    def __init__(self):
        self.ca_key_path = "ca_files/ca_key.pem"
        self.ca_cert_path = "ca_files/ca_cert.pem"
        self.ca_key = None
        self.ca_cert = None
        os.makedirs("ca_files", exist_ok=True)
        self.load_ca()

    def generate_private_key(self, password=None):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        encryption = NoEncryption() if password is None else BestAvailableEncryption(password.encode())
        return key, key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    def create_ca_cert(self, ca_key, ca_name="MyCA"):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        
        return cert, cert.public_bytes(Encoding.PEM)

    def create_csr(self, key, common_name):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(key, hashes.SHA256())
        )
        
        return csr, csr.public_bytes(Encoding.PEM)

    def sign_csr(self, csr, ca_cert, ca_key, days_valid=365):
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        
        return cert, cert.public_bytes(Encoding.PEM)

    def save_file(self, filename, data):
        with open(filename, "wb") as f:
            f.write(data)

    def load_ca(self):
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = load_pem_private_key(f.read(), password=b"ca_password")
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        else:
            self.ca_key, ca_key_pem = self.generate_private_key(password="ca_password")
            self.ca_cert, ca_cert_pem = self.create_ca_cert(self.ca_key)
            self.save_file(self.ca_key_path, ca_key_pem)
            self.save_file(self.ca_cert_path, ca_cert_pem)
            logging.info("Generated new CA key and certificate")

# Initialize CA
ca = CertificateAuthority()

# Routes
@app.route('/')
@login_required
def index():
    certificates = Certificate.query.all()
    return render_template('index.html', certificates=certificates)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Hardcoded for simplicity; use a proper user database in production
        if username == "admin" and password == "admin123":
            user = User(id=1)
            login_user(user)
            logging.info("User logged in")
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials")
            logging.warning("Failed login attempt")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    logging.info("User logged out")
    return redirect(url_for('login'))

@app.route('/generate_server', methods=['POST'])
@login_required
def generate_server():
    common_name = request.form.get('common_name', 'server.example.com')
    try:
        server_key, server_key_pem = ca.generate_private_key(password="server_password")
        server_csr, server_csr_pem = ca.create_csr(server_key, common_name)
        ca.save_file(f"ca_files/{common_name}_key.pem", server_key_pem)
        ca.save_file(f"ca_files/{common_name}_csr.pem", server_csr_pem)
        
        # Sign the CSR
        server_cert, server_cert_pem = ca.sign_csr(server_csr, ca.ca_cert, ca.ca_key)
        cert_path = f"ca_files/{common_name}_cert.pem"
        ca.save_file(cert_path, server_cert_pem)

        # Save to database
        cert = x509.load_pem_x509_certificate(server_cert_pem)
        certificate = Certificate(
            serial_number=str(cert.serial_number),
            subject=cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            cert_path=cert_path
        )
        db.session.add(certificate)
        db.session.commit()

        flash("Server certificate issued successfully")
        logging.info(f"Issued certificate for {common_name}, serial: {cert.serial_number}")
    except Exception as e:
        flash(f"Error: {str(e)}")
        logging.error(f"Error issuing certificate for {common_name}: {str(e)}")
    return redirect(url_for('index'))

@app.route('/revoke/<int:cert_id>')
@login_required
def revoke(cert_id):
    certificate = Certificate.query.get_or_404(cert_id)
    try:
        certificate.status = 'revoked'
        db.session.commit()
        flash(f"Certificate {certificate.serial_number} revoked")
        logging.info(f"Revoked certificate {certificate.serial_number}")
    except Exception as e:
        flash(f"Error: {str(e)}")
        logging.error(f"Error revoking certificate {certificate.serial_number}: {str(e)}")
    return redirect(url_for('index'))

@app.route('/download/<int:cert_id>')
@login_required
def download(cert_id):
    certificate = Certificate.query.get_or_404(cert_id)
    logging.info(f"Downloaded certificate {certificate.serial_number}")
    return send_file(certificate.cert_path, as_attachment=True)

# Generate a self-signed certificate for HTTPS (for demo purposes)
def generate_self_signed_cert():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    with open("ca_files/server.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open("ca_files/server.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

if __name__ == "__main__":
    # Create database
    with app.app_context():
        db.create_all()
    
    # Generate self-signed certificate for HTTPS
    if not os.path.exists("ca_files/server.crt") or not os.path.exists("ca_files/server.key"):
        generate_self_signed_cert()
    
    # Run Flask app with HTTPS
    app.run(host='0.0.0.0', port=5000, ssl_context=('ca_files/server.crt', 'ca_files/server.key'))