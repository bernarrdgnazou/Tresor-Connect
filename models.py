from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import enum

db = SQLAlchemy()

class UserRole(enum.Enum):
    ADMIN = "admin"
    AGENT = "agent"
    FOURNISSEUR = "fournisseur"
    TRESORIER = "tresorier"

class StatutMandat(enum.Enum):
    DEPOSE = "déposé"
    EN_COURS = "en_cours"
    VALIDE = "validé"
    REJETE = "rejeté"
    PRET_A_PAYER = "pret_a_payer"
    PAYE = "payé"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telephone = db.Column(db.String(20), nullable=False)
    nom_complet = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)
    entreprise = db.Column(db.String(200))
    service = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relations
    mandats_agent = db.relationship('Mandat', foreign_keys='Mandat.agent_id', backref='agent', lazy=True)
    mandats_fournisseur = db.relationship('Mandat', foreign_keys='Mandat.fournisseur_id', backref='fournisseur', lazy=True)
    historiques = db.relationship('HistoriqueMandat', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    otps = db.relationship('OTP', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return str(self.id)
    
    def __repr__(self):
        return f'<User {self.email} - {self.role.value}>'

class Mandat(db.Model):
    __tablename__ = 'mandats'
    
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(50), unique=True, nullable=False)
    numero_facture = db.Column(db.String(50), nullable=True)  # Ajout du champ pour le numéro de facture
    montant = db.Column(db.Numeric(10, 2), nullable=False)    # Utilisation de Numeric pour la précision des montants
    description = db.Column(db.Text)
    
    date_depot = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Date d'arrivée
    date_echeance = db.Column(db.Date, nullable=True) # Ajout de la date d'échéance. Peut être nulle si non applicable.
    date_validation = db.Column(db.DateTime, nullable=True)
    date_paiement = db.Column(db.DateTime, nullable=True)
    
    statut = db.Column(db.Enum(StatutMandat), default=StatutMandat.DEPOSE, nullable=False)
    fichier_original = db.Column(db.String(255), nullable=True)
    
    # Clés étrangères
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fournisseur_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relations
    historiques = db.relationship('HistoriqueMandat', backref='mandat', lazy=True)
    
    def __repr__(self):
        return f'<Mandat {self.reference} - {self.montant}>'
    
    # Méthode pour définir la date d'échéance (utilisée lors de la création du mandat)
    def set_date_echeance(self):
        self.date_echeance = (self.date_depot + timedelta(days=5)).date()


class HistoriqueMandat(db.Model):
    __tablename__ = 'historique_mandats'
    
    id = db.Column(db.Integer, primary_key=True)
    mandat_id = db.Column(db.Integer, db.ForeignKey('mandats.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    service = db.Column(db.String(100), nullable=False)
    commentaire = db.Column(db.Text)
    date_action = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __repr__(self):
        return f'<Historique {self.action} - {self.date_action}>'

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type_notification = db.Column(db.String(20), default='info')
    lu = db.Column(db.Boolean, default=False)
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Notification {self.message[:50]}...>'

class OTP(db.Model):
    __tablename__ = 'otps'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def is_valid(self):
        return not self.used and datetime.utcnow() < self.expires_at
    
    def __repr__(self):
        return f'<OTP {self.code} - {self.user_id}>'