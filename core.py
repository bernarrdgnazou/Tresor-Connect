import os
import click
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask.cli import with_appcontext
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import random
import string

from config import Config
from models import db, User, UserRole, Mandat, HistoriqueMandat, StatutMandat, Notification, OTP
from forms import LoginForm, OTPForm, RegistrationForm, MandatForm, TraitementMandatForm, ResetPasswordRequestForm, ResetPasswordForm

from itsdangerous import URLSafeTimedSerializer


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialisation des extensions
    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Création des dossiers nécessaires
    with app.app_context():
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    return app

app = create_app()

# Fonctions utilitaires
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['pdf', 'doc', 'docx', 'jpg', 'png']

def envoyer_sms_simulation(telephone, message):
    """Simulation d'envoi SMS - À remplacer par un vrai service SMS"""
    print(f"SMS envoyé à {telephone}: {message}")
    return True

# Commandes Flask
@app.cli.command("init-db")
@with_appcontext
def init_db_command():
    """Initialise la base de données avec des données de test"""
    try:
        # Supprimer et recréer les tables
        db.drop_all()
        db.create_all()
        
        print("Anciennes tables supprimées")
        print("Nouvelles tables créées")
        
        # Création des utilisateurs de test
        users_data = [
            {
                'email': 'admin@mandats.gov', 
                'telephone': '+221771234567',
                'nom_complet': 'Administrateur Systeme', 
                'role': UserRole.ADMIN,
                'password': 'admin123', 
                'service': 'Administration'
            },
            {
                'email': 'agent@finances.gov', 
                'telephone': '+221771234568',
                'nom_complet': 'Papa Diop', 
                'role': UserRole.AGENT,
                'password': 'agent123', 
                'service': 'Ministère des Finances'
            },
            {
                'email': 'fournisseur@entreprise.sn', 
                'telephone': '+221771234569',
                'nom_complet': 'Entreprise SARL', 
                'role': UserRole.FOURNISSEUR,
                'password': 'fournisseur123', 
                'entreprise': 'Entreprise SARL'
            },
            {
                'email': 'tresorier@finances.gov', 
                'telephone': '+221771234570',
                'nom_complet': 'Trésorier National', 
                'role': UserRole.TRESORIER,
                'password': 'tresorier123', 
                'service': 'Trésor National'
            }
        ]
        
        print("Création des utilisateurs de test...")
        
        for user_data in users_data:
            user = User(
                email=user_data['email'],
                telephone=user_data['telephone'],
                nom_complet=user_data['nom_complet'],
                role=user_data['role'],
                entreprise=user_data.get('entreprise'),
                service=user_data.get('service')
            )
            user.set_password(user_data['password'])
            db.session.add(user)
        
        db.session.commit()
        
        print("Base de données initialisée avec succès!")
        print("\nComptes de test créés :")
        print("   - Admin: admin@mandats.gov / admin123")
        print("   - Agent: agent@finances.gov / agent123")
        print("   - Fournisseur: fournisseur@entreprise.sn / fournisseur123")
        print("   - Trésorier: tresorier@finances.gov / tresorier123")
        print("\nVous pouvez maintenant lancer l'application avec: flask --app app run --debug")
        
    except Exception as e:
        print(f"Erreur lors de l'initialisation: {e}")
        db.session.rollback()

@app.cli.command("create-db")
@with_appcontext
def create_db_command():
    """Crée simplement les tables sans données de test"""
    try:
        db.create_all()
        print("Tables créées avec succès!")
    except Exception as e:
        print(f"Erreur: {e}")

# ============================================================================
# ROUTES PRINCIPALES
# ============================================================================

@app.route('/')
def home():
    """Page d'accueil pour les utilisateurs non connectés"""
    return render_template('default/index.html')

@app.route('/faq')
def faq():
    """Page FAQ"""
    return render_template('default/faq.html')

@app.route('/fonction')
def fonction():
    """Page des fonctionnalités"""
    return render_template('default/fonction.html')

@app.route('/traitement')
def traitement():
    """Page de traitement"""
    return render_template('default/traitement.html')

# ============================================================================
# AUTHENTIFICATION
# ============================================================================

@app.route('/connexion', methods=['GET', 'POST'])
def connexion():
    """Page de connexion"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and user.check_password(form.password.data) and user.is_active:
            # Générer OTP
            otp_code = generate_otp()
            otp = OTP(
                user_id=user.id,
                code=otp_code,
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp)
            db.session.commit()
            
            # Envoyer SMS (simulation)
            message = f"Votre code de vérification: {otp_code}"
            envoyer_sms_simulation(user.telephone, message)
            
            flash('Un code OTP a été envoyé à votre téléphone', 'info')
            return redirect(url_for('verify_otp', user_id=user.id))
        else:
            flash('Email ou mot de passe incorrect', 'danger')
    
    return render_template('default/connexion.html', form=form)

@app.route('/verify-otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    """Vérification OTP"""
    user = User.query.get_or_404(user_id)
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = OTPForm()
    if form.validate_on_submit():
        valid_otp = OTP.query.filter_by(
            user_id=user_id, 
            code=form.otp_code.data, 
            used=False
        ).filter(OTP.expires_at > datetime.utcnow()).first()
        
        if valid_otp:
            valid_otp.used = True
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=True)
            flash('Connexion réussie!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Code OTP invalide ou expiré', 'danger')
    
    return render_template('default/traitement.html', form=form, user=user)

@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    """Page d'inscription"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    # Récupérer la liste des services disponibles (optionnel)
    # services = ['Ministère des Finances', 'Trésor National', 'Service Régional X', etc.]
    
    if form.validate_on_submit():
        # Vérifier si l'email existe déjà
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Cet email est déjà utilisé. Veuillez utiliser un autre email.', 'danger')
            return render_template('inscription.html', form=form)
        
        try:
            user = User(
                email=form.email.data,
                telephone=form.telephone.data,
                nom_complet=form.nom_complet.data,
                role=UserRole(form.role.data),
                entreprise=form.entreprise.data if form.role.data == 'fournisseur' else None,
                service=form.service.data if form.role.data in ['agent', 'tresorier'] else None
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Compte créé avec succès! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('connexion'))
            
        except Exception as e:
            db.session.rollback()
            flash('Une erreur est survenue lors de la création du compte. Veuillez réessayer.', 'danger')
    
    return render_template('default/inscription.html', form=form)

# Configuration pour les tokens de réinitialisation
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    """Demande de réinitialisation de mot de passe"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            # Générer un token de réinitialisation
            token = s.dumps(user.email, salt='password-reset-salt')
            
            # Construire le lien de réinitialisation
            reset_url = url_for('reset_password_token', token=token, _external=True)
            
            # Envoyer l'email (simulation pour l'instant)
            print(f"Lien de réinitialisation pour {user.email}: {reset_url}")
            
            # En production, vous utiliseriez un service comme SendGrid, Mailgun, etc.
            # send_password_reset_email(user, reset_url)
        
        # Toujours afficher le même message pour des raisons de sécurité
        flash('Si votre email existe dans notre système, vous recevrez un lien de réinitialisation.', 'info')
        return redirect(url_for('connexion'))
    
    return render_template('default/reset_password_request.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    """Réinitialisation du mot de passe avec token"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    try:
        # Vérifier et décoder le token (valide pendant 1 heure)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('Le lien de réinitialisation est invalide ou a expiré.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Utilisateur non trouvé.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        
        flash('Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password_confirm.html', form=form, token=token)



# À ajouter à app.py pour l'envoi d'emails en production
def send_password_reset_email(user, reset_url):
    """Envoie un email de réinitialisation de mot de passe"""
    # Exemple avec Flask-Mail (à installer: pip install flask-mail)
    from flask_mail import Message
    from app import mail
    
    msg = Message(
        subject='Réinitialisation de votre mot de passe - TRÉSOR CONNECT',
        recipients=[user.email],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    
    msg.body = f'''
Bonjour {user.nom_complet},

Vous avez demandé la réinitialisation de votre mot de passe.

Cliquez sur le lien suivant pour réinitialiser votre mot de passe :
{reset_url}

Ce lien expirera dans 1 heure.

Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email.

Cordialement,
L'équipe TRÉSOR CONNECT
'''
    
    msg.html = f'''
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <h2 style="color: #333;">Réinitialisation de mot de passe</h2>
    <p>Bonjour <strong>{user.nom_complet}</strong>,</p>
    <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
    <p>
        <a href="{reset_url}" style="background-color: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Réinitialiser mon mot de passe
        </a>
    </p>
    <p><small>Ce lien expirera dans 1 heure.</small></p>
    <p>Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email.</p>
    <hr>
    <p>Cordialement,<br>L'équipe TRÉSOR CONNECT</p>
</div>
'''
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Erreur envoi email: {e}")
        return False



@app.route('/logout')
@login_required
def logout():
    """Déconnexion"""
    logout_user()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('home'))

# ============================================================================
# DASHBOARD ET ROUTES COMMUNES
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Tableau de bord selon le rôle de l'utilisateur"""
    # Statistiques selon le rôle
    if current_user.role == UserRole.AGENT:
        mandats_total = Mandat.query.filter_by(agent_id=current_user.id).count()
        mandats_en_cours = Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.EN_COURS).count()
        mandats_valides = Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.VALIDE).count()
        
        return render_template('user_agent/agent_dashboard.html',
                             mandats_total=mandats_total,
                             mandats_en_cours=mandats_en_cours,
                             mandats_valides=mandats_valides)
    
    elif current_user.role == UserRole.FOURNISSEUR:
        mandats_total = Mandat.query.filter_by(fournisseur_id=current_user.id).count()
        mandats_attente = Mandat.query.filter_by(fournisseur_id=current_user.id, statut=StatutMandat.EN_COURS).count()
        mandats_payes = Mandat.query.filter_by(fournisseur_id=current_user.id, statut=StatutMandat.PAYE).count()
        
        # Calcul du montant total
        montant_total = db.session.query(db.func.sum(Mandat.montant)).filter_by(
            fournisseur_id=current_user.id, 
            statut=StatutMandat.PAYE
        ).scalar() or 0
        
        return render_template('user_fournisseur/fournisseur_dashboard.html',
                             mandats_total=mandats_total,
                             mandats_attente=mandats_attente,
                             mandats_payes=mandats_payes,
                             montant_total=montant_total)
    
    elif current_user.role == UserRole.TRESORIER:
        mandats_total = Mandat.query.count()
        mandats_en_cours = Mandat.query.filter_by(statut=StatutMandat.EN_COURS).count()
        mandats_valides = Mandat.query.filter_by(statut=StatutMandat.VALIDE).count()
        
        return render_template('user_agent/agent_dashboard.html',  # Réutiliser le template agent pour le trésorier
                             mandats_total=mandats_total,
                             mandats_en_cours=mandats_en_cours,
                             mandats_valides=mandats_valides)
    
    elif current_user.role == UserRole.ADMIN:
        stats = {
            'utilisateurs_total': User.query.count(),
            'utilisateurs_agent': User.query.filter_by(role=UserRole.AGENT).count(),
            'utilisateurs_fournisseur': User.query.filter_by(role=UserRole.FOURNISSEUR).count(),
            'utilisateurs_tresorier': User.query.filter_by(role=UserRole.TRESORIER).count(),
            'mandats_total': Mandat.query.count(),
            'mandats_deposes': Mandat.query.filter_by(statut=StatutMandat.DEPOSE).count(),
            'mandats_en_cours': Mandat.query.filter_by(statut=StatutMandat.EN_COURS).count(),
            'mandats_valides': Mandat.query.filter_by(statut=StatutMandat.VALIDE).count(),
            'notifications_total': Notification.query.count()
        }
        
        return render_template('data_admin/admin_dashboard.html', stats=stats)
    
    return redirect(url_for('home'))

# ============================================================================
# GESTION DES MANDATS - AGENT
# ============================================================================

@app.route('/mandats/deposer', methods=['GET', 'POST'])
@login_required
def deposer_mandat():
    """Déposer un nouveau mandat (Agent seulement)"""
    if current_user.role != UserRole.AGENT:
        flash('Accès réservé aux agents', 'danger')
        return redirect(url_for('dashboard'))
    
    form = MandatForm()
    # Récupérer la liste des fournisseurs pour le select
    fournisseurs = User.query.filter_by(role=UserRole.FOURNISSEUR).all()
    form.fournisseur_id.choices = [(f.id, f.nom_complet) for f in fournisseurs]
    
    if form.validate_on_submit():
        # Gestion du fichier
        filename = None
        if form.fichier.data:
            file = form.fichier.data
            if allowed_file(file.filename):
                filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
        
        mandat = Mandat(
            reference=form.reference.data,
            montant=form.montant.data,
            description=form.description.data,
            agent_id=current_user.id,
            fournisseur_id=form.fournisseur_id.data,
            fichier_original=filename
        )
        
        db.session.add(mandat)
        db.session.flush()  # Pour obtenir l'ID du mandat
        
        # Historique
        historique = HistoriqueMandat(
            mandat_id=mandat.id,
            action="Dépôt du mandat",
            service=current_user.service or "Service non spécifié",
            commentaire="Mandat déposé par l'agent",
            user_id=current_user.id
        )
        db.session.add(historique)
        
        # Notification au fournisseur
        notification = Notification(
            user_id=form.fournisseur_id.data,
            message=f"Nouveau mandat {form.reference.data} déposé - Montant: {form.montant.data} FCFA",
            type_notification="info"
        )
        db.session.add(notification)
        
        db.session.commit()
        flash('Mandat déposé avec succès', 'success')
        return redirect(url_for('mes_mandats'))
    
    return render_template('user_agent/deposer_mandat.html', form=form)

@app.route('/mandats/mes-mandats')
@login_required
def mes_mandats():
    """Liste des mandats selon le rôle"""
    if current_user.role == UserRole.AGENT:
        mandats = Mandat.query.filter_by(agent_id=current_user.id).order_by(Mandat.date_depot.desc()).all()
        return render_template('user_agent/mes_mandats.html', mandats=mandats)
    
    elif current_user.role == UserRole.FOURNISSEUR:
        mandats = Mandat.query.filter_by(fournisseur_id=current_user.id).order_by(Mandat.date_depot.desc()).all()
        return render_template('user_fournisseur/mes_mandats_fournisseur.html', mandats=mandats)
    
    else:
        mandats = Mandat.query.order_by(Mandat.date_depot.desc()).all()
        return render_template('user_agent/mes_mandats.html', mandats=mandats)

@app.route('/mandats/suivi/<int:mandat_id>')
@login_required
def suivi_mandat(mandat_id):
    """Suivi détaillé d'un mandat"""
    mandat = Mandat.query.get_or_404(mandat_id)
    
    # Vérification des permissions
    if current_user.role not in [UserRole.ADMIN, UserRole.TRESORIER]:
        if mandat.agent_id != current_user.id and mandat.fournisseur_id != current_user.id:
            flash('Accès non autorisé', 'danger')
            return redirect(url_for('dashboard'))
    
    historique = HistoriqueMandat.query.filter_by(mandat_id=mandat_id).order_by(HistoriqueMandat.date_action.desc()).all()
    
    if current_user.role == UserRole.FOURNISSEUR:
        return render_template('user_fournisseur/suivi_mandat_fournisseur.html', mandat=mandat, historique=historique)
    else:
        return render_template('user_agent/suivi_mandat.html', mandat=mandat, historique=historique)

@app.route('/mandats/detail/<int:mandat_id>')
@login_required
def mandat_detail(mandat_id):
    """Détail d'un mandat"""
    mandat = Mandat.query.get_or_404(mandat_id)
    
    # Vérification des permissions
    if current_user.role not in [UserRole.ADMIN, UserRole.TRESORIER]:
        if mandat.agent_id != current_user.id and mandat.fournisseur_id != current_user.id:
            flash('Accès non autorisé', 'danger')
            return redirect(url_for('dashboard'))
    
    if current_user.role == UserRole.FOURNISSEUR:
        return render_template('user_fournisseur/mandat_detail_fournisseur.html', mandat=mandat)
    else:
        return render_template('user_agent/mandat_detail.html', mandat=mandat)

# ============================================================================
# TRÉSORERIE - TRAITEMENT DES MANDATS
# ============================================================================

@app.route('/tresorerie/mandats')
@login_required
def mandats_a_traiter():
    """Liste des mandats à traiter (Trésorier/Admin seulement)"""
    if current_user.role not in [UserRole.TRESORIER, UserRole.ADMIN]:
        flash('Accès réservé au trésor', 'danger')
        return redirect(url_for('dashboard'))
    
    statut = request.args.get('statut', 'en_cours')
    try:
        mandats = Mandat.query.filter_by(statut=StatutMandat(statut)).order_by(Mandat.date_depot.asc()).all()
    except ValueError:
        mandats = Mandat.query.filter_by(statut=StatutMandat.EN_COURS).order_by(Mandat.date_depot.asc()).all()
        statut = 'en_cours'
    
    return render_template('user_agent/mes_mandats.html', mandats=mandats, statut=statut)

@app.route('/tresorerie/traiter/<int:mandat_id>', methods=['POST'])
@login_required
def traiter_mandat(mandat_id):
    """Traiter un mandat (Trésorier/Admin seulement)"""
    if current_user.role not in [UserRole.TRESORIER, UserRole.ADMIN]:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('dashboard'))
    
    mandat = Mandat.query.get_or_404(mandat_id)
    action = request.form.get('action')
    commentaire = request.form.get('commentaire', '')
    
    actions = {
        'valider': (StatutMandat.VALIDE, "Validation du mandat"),
        'rejeter': (StatutMandat.REJETE, "Rejet du mandat"),
        'pret_a_payer': (StatutMandat.PRET_A_PAYER, "Mandat prêt à payer"),
        'payer': (StatutMandat.PAYE, "Paiement effectué")
    }
    
    if action in actions:
        nouveau_statut, message_action = actions[action]
        mandat.statut = nouveau_statut
        
        if action == 'payer':
            mandat.date_paiement = datetime.utcnow()
        
        # Historique
        historique = HistoriqueMandat(
            mandat_id=mandat.id,
            action=message_action,
            service=current_user.service or "Trésor",
            commentaire=commentaire,
            user_id=current_user.id
        )
        db.session.add(historique)
        
        # Notifications
        for user_id in [mandat.agent_id, mandat.fournisseur_id]:
            notification = Notification(
                user_id=user_id,
                message=f"Mandat {mandat.reference}: {message_action}",
                type_notification="success" if action in ['valider', 'payer'] else "warning"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash(f'Mandat {message_action.lower()} avec succès', 'success')
    else:
        flash('Action non reconnue', 'danger')
    
    return redirect(url_for('mandats_a_traiter'))

# ============================================================================
# ADMINISTRATION
# ============================================================================

@app.route('/admin/database')
@login_required
def admin_database():
    """Administration de la base de données (Admin seulement)"""
    if current_user.role != UserRole.ADMIN:
        flash('Accès réservé aux administrateurs', 'danger')
        return redirect(url_for('dashboard'))
    
    stats = {
        'users': User.query.count(),
        'users_agent': User.query.filter_by(role=UserRole.AGENT).count(),
        'users_fournisseur': User.query.filter_by(role=UserRole.FOURNISSEUR).count(),
        'users_tresorier': User.query.filter_by(role=UserRole.TRESORIER).count(),
        'mandats': Mandat.query.count(),
        'mandats_deposes': Mandat.query.filter_by(statut=StatutMandat.DEPOSE).count(),
        'mandats_en_cours': Mandat.query.filter_by(statut=StatutMandat.EN_COURS).count(),
        'mandats_valides': Mandat.query.filter_by(statut=StatutMandat.VALIDE).count(),
        'mandats_pret_a_payer': Mandat.query.filter_by(statut=StatutMandat.PRET_A_PAYER).count(),
        'mandats_payes': Mandat.query.filter_by(statut=StatutMandat.PAYE).count(),
        'notifications': Notification.query.count(),
        'notifications_non_lues': Notification.query.filter_by(lu=False).count()
    }
    
    return render_template('data_admin/admin_database.html', stats=stats)

@app.route('/admin/utilisateurs')
@login_required
def admin_users():
    """Gestion des utilisateurs (Admin seulement)"""
    if current_user.role != UserRole.ADMIN:
        flash('Accès réservé aux administrateurs', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('data_admin/admin_users.html', users=users)

@app.route('/admin/rapports')
@login_required
def admin_reports():
    """Rapports administratifs (Admin seulement)"""
    if current_user.role != UserRole.ADMIN:
        flash('Accès réservé aux administrateurs', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('data_admin/admin_reports.html')

# ============================================================================
# PROFIL ET PARAMÈTRES
# ============================================================================

@app.route('/profil')
@login_required
def profil():
    """Page de profil utilisateur"""
    if current_user.role == UserRole.AGENT:
        return render_template('user_agent/agent_profile.html')
    elif current_user.role == UserRole.FOURNISSEUR:
        return render_template('user_fournisseur/fournisseur_profile.html')
    else:
        return render_template('user_agent/agent_profile.html')  # Réutiliser pour admin/trésorier

@app.route('/statistiques')
@login_required
def statistiques():
    """Page de statistiques"""
    if current_user.role == UserRole.AGENT:
        return render_template('user_agent/agent_statistiques.html')
    elif current_user.role == UserRole.FOURNISSEUR:
        return render_template('user_fournisseur/fournisseur_statistiques.html')
    else:
        return render_template('user_agent/agent_statistiques.html')

@app.route('/historique-paiements')
@login_required
def historique_paiements():
    """Historique des paiements (Fournisseur seulement)"""
    if current_user.role != UserRole.FOURNISSEUR:
        flash('Accès réservé aux fournisseurs', 'danger')
        return redirect(url_for('dashboard'))
    
    mandats_payes = Mandat.query.filter_by(
        fournisseur_id=current_user.id, 
        statut=StatutMandat.PAYE
    ).order_by(Mandat.date_paiement.desc()).all()
    
    return render_template('user_fournisseur/historique_paiements.html', mandats=mandats_payes)

# ============================================================================
# NOTIFICATIONS
# ============================================================================

@app.route('/notifications')
@login_required
def notifications():
    """Page des notifications"""
    notifications_list = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.date_creation.desc()).all()
    return render_template('default/traitement.html', notifications=notifications_list)

@app.route('/api/notifications/non-lues')
@login_required
def api_notifications_non_lues():
    """API pour les notifications non lues"""
    notifications_non_lues = Notification.query.filter_by(user_id=current_user.id, lu=False).order_by(Notification.date_creation.desc()).limit(10).all()
    
    return jsonify([{
        'id': n.id,
        'message': n.message,
        'type': n.type_notification,
        'date_creation': n.date_creation.strftime('%d/%m/%Y %H:%M') if n.date_creation else ''
    } for n in notifications_non_lues])

@app.route('/api/notifications/marquer-lue/<int:notification_id>', methods=['POST'])
@login_required
def marquer_notification_lue(notification_id):
    """Marquer une notification comme lue"""
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id == current_user.id:
        notification.lu = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 403

# ============================================================================
# UTILITAIRES
# ============================================================================

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """Accès aux fichiers uploadés"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/init-db-test')
def init_db_test():
    """Route de test pour initialiser la base de données"""
    try:
        db.drop_all()
        db.create_all()
        
        users_data = [
            {
                'email': 'admin@mandats.gov', 'telephone': '+221771234567',
                'nom_complet': 'Administrateur Systeme', 'role': UserRole.ADMIN,
                'password': 'admin123', 'service': 'Administration'
            },
            {
                'email': 'agent@finances.gov', 'telephone': '+221771234568',
                'nom_complet': 'Papa Diop', 'role': UserRole.AGENT,
                'password': 'agent123', 'service': 'Ministère des Finances'
            },
            {
                'email': 'fournisseur@entreprise.sn', 'telephone': '+221771234569',
                'nom_complet': 'Entreprise SARL', 'role': UserRole.FOURNISSEUR,
                'password': 'fournisseur123', 'entreprise': 'Entreprise SARL'
            },
            {
                'email': 'tresorier@finances.gov', 'telephone': '+221771234570',
                'nom_complet': 'Trésorier National', 'role': UserRole.TRESORIER,
                'password': 'tresorier123', 'service': 'Trésor National'
            }
        ]
        
        for user_data in users_data:
            user = User(
                email=user_data['email'],
                telephone=user_data['telephone'],
                nom_complet=user_data['nom_complet'],
                role=user_data['role'],
                entreprise=user_data.get('entreprise'),
                service=user_data.get('service')
            )
            user.set_password(user_data['password'])
            db.session.add(user)
        
        db.session.commit()
        
        return "Base de données initialisée avec succès! <a href='/'>Retour à l'accueil</a>"
    except Exception as e:
        return f"Erreur: {e}"

# ============================================================================
# EXECUTION
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True)