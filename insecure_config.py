"""
Configuraciones inseguras para testing de herramientas SAST
"""

# Configuración Flask insegura
class Config:
    SECRET_KEY = 'hardcoded-secret-key-123'
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db?check_same_thread=False'
    
    # B105: Hardcoded passwords
    DB_PASSWORD = 'admin123'
    JWT_SECRET = 'jwt-secret-key'
    API_TOKEN = 'token-12345'
    
    # B104: Bind to all interfaces
    HOST = '0.0.0.0'
    PORT = 5000

# Configuración de logging insegura
import logging
logging.basicConfig(level=logging.DEBUG)

# Configuración SSL insegura
import ssl
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Configuración de requests insegura
import requests
requests.packages.urllib3.disable_warnings()

# Variables de entorno hardcodeadas
os.environ['DATABASE_URL'] = 'postgresql://user:password@localhost/db'
os.environ['SECRET_KEY'] = 'another-hardcoded-secret'