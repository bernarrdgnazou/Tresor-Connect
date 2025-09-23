import os
from datetime import timedelta

class Config:
    # Clé secrète
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'votre-cle-secrete-tres-longue-ici'
    
    # Configuration de la base de données
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///data_base0.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configuration de l'upload
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Configuration de session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Configuration SMS (simulation)
    SMS_API_KEY = os.environ.get('SMS_API_KEY', 'simulation')
    SMS_API_SECRET = os.environ.get('SMS_API_SECRET', 'simulation')