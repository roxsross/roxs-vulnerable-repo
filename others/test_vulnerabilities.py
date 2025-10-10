#!/usr/bin/env python3
"""
Archivo de prueba con vulnerabilidades intencionadas para testing de Bandit
Este archivo contiene patrones que Bandit debería detectar
"""

import os
import subprocess
import pickle
import yaml
import hashlib
import random
import tempfile

# B105: Hardcoded password string
SECRET_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# B104: Hardcoded bind all interfaces
def start_server():
    app.run(host='0.0.0.0', port=5000, debug=True)

# B602: subprocess with shell=True
def execute_command(user_input):
    subprocess.call(user_input, shell=True)

# B301: Pickle usage (unsafe deserialization)
def load_data(data):
    return pickle.loads(data)

# B506: YAML load (unsafe)
def load_config(config_file):
    with open(config_file, 'r') as f:
        return yaml.load(f)

# B303: MD5 usage (weak hash)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# B311: Random for security purposes
def generate_token():
    return str(random.random())

# B108: Hardcoded temp directory
TEMP_DIR = "/tmp/myapp"

# B107: Hardcoded password in function default
def connect_db(password="defaultpass"):
    pass

# B322: Input usage (Python 2 style)
def get_user_input():
    return input("Enter command: ")

# B608: SQL injection pattern
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return execute_query(query)

# B110: Try/except pass
def risky_operation():
    try:
        dangerous_function()
    except:
        pass

# B201: Flask debug mode
from flask import Flask
app = Flask(__name__)
app.run(debug=True)

# B324: Insecure hash functions
def weak_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()

# B605: Start process with shell
def run_command(cmd):
    os.system(cmd)

# B102: exec usage
def execute_code(code):
    exec(code)

# B101: assert usage
def validate_user(user):
    assert user.is_admin, "User must be admin"

if __name__ == "__main__":
    print("This file contains intentional vulnerabilities for Bandit testing")