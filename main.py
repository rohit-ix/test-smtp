import os
import smtplib
import dns.resolver
import socket
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

def is_valid_email(email):
    """Validate email format using regex."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

def get_mx_record(domain):
    """Fetch the MX record for the given domain."""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return str(mx_records[0].exchange)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        print(f"DNS Resolution Error for {domain}")
        return None
    except Exception:
        print(f"Unexpected DNS error for {domain}")
        return None

def verify_email(email):
    """Perform email verification using SMTP."""
    if not is_valid_email(email):
        return {"code": 1, "status": "Invalid", "message": "Invalid email format"}
    
    domain = email.split('@')[-1]
    mx_server = get_mx_record(domain)
    
    if not mx_server:
        return {"code": 4, "status": "Unknown", "message": "No mail server found"}
    
    try:
        with smtplib.SMTP(mx_server, 587, timeout=10) as server:
            server.starttls()
            server.helo()
            server.mail('test@example.com')
            code, _ = server.rcpt(email)
            
            if code == 250:
                return {"code": 0, "status": "Valid", "message": "Valid email"}
            elif code == 550:
                return {"code": 1, "status": "Invalid", "message": "Email does not exist"}
            else:
                return {"code": 4, "status": "Unknown", "message": "Email rejected or unknown issue"}
    except (socket.timeout, smtplib.SMTPConnectError):
        return {"code": 4, "status": "Unknown", "message": "SMTP connection timeout or refused"}
    except smtplib.SMTPException:
        return {"code": 4, "status": "Unknown", "message": "SMTP error occurred"}

@app.route('/validate', methods=['POST'])
def validate_email():
    """Cloud Run API Handler"""
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"error": "Email parameter is required"}), 400

        result = verify_email(email)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
