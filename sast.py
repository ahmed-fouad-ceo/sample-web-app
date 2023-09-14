# Insecure code for demonstration purposes

# Vulnerability 1: SQL Injection
def insecure_sql(query):
    import sqlite3
    conn = sqlite3.connect('insecure.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + query + "'")
    result = cursor.fetchall()
    conn.close()
    return result

# Vulnerability 2: Cross-Site Scripting (XSS)
def insecure_xss(input_data):
    return "<p>" + input_data + "</p>"

# Vulnerability 3: Insecure Deserialization
import pickle

def insecure_deserialization(data):
    return pickle.loads(data)

# Vulnerability 4: Command Injection
import subprocess

def insecure_command_injection(cmd):
    result = subprocess.check_output(cmd, shell=True)
    return result

# Vulnerability 5: Hardcoded Credentials
def insecure_credentials():
    username = "admin"
    password = "password123"
    return (username, password)

if __name__ == "__main__":
    # Example usage of the insecure functions
    query = "admin' OR '1'='1"
    result = insecure_sql(query)
    print(result)

    input_data = "<script>alert('XSS');</script>"
    output = insecure_xss(input_data)
    print(output)

    serialized_data = b'\x80\x03C\nhardcoded_password\nq\x00.'
    deserialized = insecure_deserialization(serialized_data)
    print(deserialized)

    command = "ls /"
    result = insecure_command_injection(command)
    print(result)

    credentials = insecure_credentials()
    print(credentials)
