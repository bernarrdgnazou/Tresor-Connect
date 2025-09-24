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
    login_manager.login_view = 'connexion'
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

    # 🔎 Récupérer le dernier OTP généré pour ce user
    latest_otp = OTP.query.filter_by(user_id=user_id).order_by(OTP.id.desc()).first()
    otp_code = latest_otp.code if latest_otp else None
    
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
    
    return render_template('default/verification_otp.html', form=form, user=user, otp_code=otp_code)

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
        return redirect(url_for('connexion'))
    
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



@app.route('/deconnexion', methods=['GET', 'POST'])
@login_required
def logout():
    """Déconnexion sécurisée"""
    if request.method == 'POST':
        logout_user()
        flash('Vous avez été déconnecté avec succès.', 'info')
        return redirect(url_for('home'))
    
    # Si méthode GET, afficher une page de confirmation
    return render_template('default/deconnexion_confirm.html')

# ============================================================================
# API POUR LE PROFIL UTILISATEUR
# ============================================================================

@app.route('/api/user/profile', methods=['GET', 'POST'])
@login_required
def api_user_profile():
    """API pour la gestion du profil utilisateur"""
    if request.method == 'GET':
        return jsonify({
            'email': current_user.email,
            'telephone': current_user.telephone,
            'nom_complet': current_user.nom_complet,
            'role': current_user.role.value,
            'entreprise': current_user.entreprise,
            'service': current_user.service,
            'date_creation': current_user.date_creation.strftime('%d/%m/%Y') if current_user.date_creation else ''
        })
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validation des données
            if 'email' in data and data['email'] != current_user.email:
                existing_user = User.query.filter_by(email=data['email']).first()
                if existing_user:
                    return jsonify({'error': 'Cet email est déjà utilisé'}), 400
                current_user.email = data['email']
            
            if 'telephone' in data:
                current_user.telephone = data['telephone']
            
            if 'nom_complet' in data:
                current_user.nom_complet = data['nom_complet']
            
            if 'entreprise' in data:
                current_user.entreprise = data['entreprise']
            
            if 'service' in data:
                current_user.service = data['service']
            
            db.session.commit()
            return jsonify({'message': 'Profil mis à jour avec succès'})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

@app.route('/api/user/change-password', methods=['POST'])
@login_required
def api_change_password():
    """API pour changer le mot de passe"""
    try:
        data = request.get_json()
        
        # Validation des données
        if not data.get('current_password'):
            return jsonify({'success': False, 'error': 'Mot de passe actuel requis'})
        
        if not data.get('new_password'):
            return jsonify({'success': False, 'error': 'Nouveau mot de passe requis'})
        
        if data['new_password'] != data.get('confirm_password', ''):
            return jsonify({'success': False, 'error': 'Les mots de passe ne correspondent pas'})
        
        # Vérifier le mot de passe actuel
        if not current_user.check_password(data['current_password']):
            return jsonify({'success': False, 'error': 'Mot de passe actuel incorrect'})
        
        # Changer le mot de passe
        current_user.set_password(data['new_password'])
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Mot de passe changé avec succès'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/user/stats')
@login_required
def api_user_stats():
    """API pour les statistiques utilisateur"""
    try:
        if current_user.role == UserRole.AGENT:
            stats = {
                'mandats_total': Mandat.query.filter_by(agent_id=current_user.id).count(),
                'mandats_en_cours': Mandat.query.filter_by(
                    agent_id=current_user.id, 
                    statut=StatutMandat.EN_COURS
                ).count(),
                'mandats_valides': Mandat.query.filter_by(
                    agent_id=current_user.id, 
                    statut=StatutMandat.VALIDE
                ).count(),
                'mandats_payes': Mandat.query.filter_by(
                    agent_id=current_user.id, 
                    statut=StatutMandat.PAYE
                ).count()
            }
            
        elif current_user.role == UserRole.FOURNISSEUR:
            mandats_payes = Mandat.query.filter_by(
                fournisseur_id=current_user.id, 
                statut=StatutMandat.PAYE
            ).all()
            
            stats = {
                'mandats_total': Mandat.query.filter_by(fournisseur_id=current_user.id).count(),
                'mandats_attente': Mandat.query.filter_by(
                    fournisseur_id=current_user.id, 
                    statut=StatutMandat.EN_COURS
                ).count(),
                'mandats_payes': len(mandats_payes),
                'montant_total': sum(mandat.montant for mandat in mandats_payes)
            }
            
        else:
            stats = {
                'mandats_total': Mandat.query.count(),
                'mandats_en_cours': Mandat.query.filter_by(statut=StatutMandat.EN_COURS).count(),
                'mandats_valides': Mandat.query.filter_by(statut=StatutMandat.VALIDE).count(),
                'mandats_payes': Mandat.query.filter_by(statut=StatutMandat.PAYE).count()
            }
            
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500    

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
        mandats_payes = Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.PAYE).count()
        mandats_recents = Mandat.query.filter_by(agent_id=current_user.id).order_by(Mandat.date_depot.desc()).limit(5).all()
        
        return render_template('user_agent/agent_dashboard.html',
                             mandats_total=mandats_total,
                             mandats_en_cours=mandats_en_cours,
                             mandats_valides=mandats_valides,
                             mandats_payes=mandats_payes,
                             mandats_recents=mandats_recents)
    
    elif current_user.role == UserRole.FOURNISSEUR:
        # Statistiques pour fournisseur
        mandats_total = Mandat.query.filter_by(fournisseur_id=current_user.id).count()
        mandats_attente = Mandat.query.filter_by(
            fournisseur_id=current_user.id, 
            statut=StatutMandat.EN_COURS
        ).count()
        mandats_payes = Mandat.query.filter_by(
            fournisseur_id=current_user.id, 
            statut=StatutMandat.PAYE
        ).count()
        
        # Calcul du montant total des mandats payés
        mandats_payes_query = Mandat.query.filter_by(
            fournisseur_id=current_user.id, 
            statut=StatutMandat.PAYE
        ).all()
        montant_total = sum(mandat.montant for mandat in mandats_payes_query)
        
        # Mandats récents (5 derniers)
        mandats_recents = Mandat.query.filter_by(
            fournisseur_id=current_user.id
        ).order_by(Mandat.date_depot.desc()).limit(5).all()
        
        # Prochain paiement (le plus ancien mandat validé non payé)
        prochain_paiement = Mandat.query.filter_by(
            fournisseur_id=current_user.id,
            statut=StatutMandat.VALIDE
        ).order_by(Mandat.date_depot.asc()).first()
        
        # Notifications non lues
        notifications_non_lues = Notification.query.filter_by(
            user_id=current_user.id, 
            lu=False
        ).count()
        
        return render_template('user_fournisseur/fournisseur_dashboard.html',
                             mandats_total=mandats_total,
                             mandats_attente=mandats_attente,
                             mandats_payes=mandats_payes,
                             montant_total=montant_total,
                             mandats_recents=mandats_recents,
                             prochain_paiement=prochain_paiement,
                             notifications_non_lues=notifications_non_lues)
    
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

def allowed_file(filename):
    """Vérifie le type de fichier autorisé."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

@app.route('/mandats/deposer', methods=['GET', 'POST'])
@login_required
def deposer_mandat():
    """Déposer un nouveau mandat (Agent seulement)."""
    if current_user.role != UserRole.AGENT:
        flash('Accès réservé aux agents', 'danger')
        return redirect(url_for('dashboard'))

    form = MandatForm()
    fournisseurs = User.query.filter_by(role=UserRole.FOURNISSEUR).all()
    form.fournisseur_id.choices = [(f.id, f.nom_complet) for f in fournisseurs]

    if form.validate_on_submit():
        filename = None
        if form.fichier.data:
            try:
                if allowed_file(form.fichier.data.filename):
                    filename = secure_filename(f"{datetime.utcnow().timestamp()}_{form.fichier.data.filename}")
                    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                    form.fichier.data.save(file_path)
                else:
                    flash('Type de fichier non autorisé.', 'danger')
                    return redirect(url_for('deposer_mandat'))
            except Exception as e:
                flash(f'Erreur lors de l\'upload du fichier : {e}', 'danger')
                return redirect(url_for('deposer_mandat'))

        mandat = Mandat(
            reference=form.reference.data,
            numero_facture=form.numero_facture.data,
            montant=form.montant.data,
            description=form.description.data,
            agent_id=current_user.id,
            fournisseur_id=form.fournisseur_id.data,
            fichier_original=filename,
            date_depot=datetime.utcnow()
        )
        mandat.set_date_echeance()

        db.session.add(mandat)
        db.session.commit()

        # Enregistrement de l'historique initial
        historique = HistoriqueMandat(
            mandat_id=mandat.id,
            action="Dépôt du mandat",
            service=current_user.service or "Service non spécifié",
            commentaire="Mandat déposé par l'agent",
            user_id=current_user.id
        )
        db.session.add(historique)

        # Notification du fournisseur
        notification = Notification(
            user_id=form.fournisseur_id.data,
            message=f"Nouveau mandat {mandat.reference} déposé. Montant: {mandat.montant} FCFA.",
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
    # Base query selon le rôle
    if current_user.role.value == 'agent':
        base_query = Mandat.query.filter_by(agent_id=current_user.id)
    elif current_user.role.value == 'fournisseur':
        base_query = Mandat.query.filter_by(fournisseur_id=current_user.id)
    else:
        base_query = Mandat.query
    
    # Récupérer les mandats
    mandats = base_query.all()
    
    # Calculer les statistiques avec des requêtes directes (plus efficace)
    stats = {
        'mandats_total': base_query.count(),
        'mandats_en_cours': base_query.filter_by(statut='en_cours').count(),
        'mandats_valides': base_query.filter(Mandat.statut.in_(['validé', 'pret_a_payer'])).count(),
        'mandats_payes': base_query.filter_by(statut='payé').count(),
        'mandats_rejetes': base_query.filter_by(statut='rejeté').count()
    }
    
    return render_template('user_agent/mes_mandats.html', 
                         mandats=mandats, 
                         stats=stats,
                         today=datetime.now().date())

@app.route('/suivi-mandat/<int:mandat_id>')
@login_required
def suivi_mandat(mandat_id):
    mandat = Mandat.query.get_or_404(mandat_id)
    
    # Vérifier les permissions
    if not (current_user.role.value in ['admin', 'tresorier'] or 
            mandat.agent_id == current_user.id or 
            mandat.fournisseur_id == current_user.id):
        abort(403)
    
    # Calcul des jours restants
    jours_restants = None
    if mandat.date_echeance:
        today = datetime.now().date()
        jours_restants = (mandat.date_echeance - today).days
    
    # Calcul du pourcentage de progression
    progress_mapping = {
        'en_cours': 25,
        'validé': 50,
        'pret_a_payer': 75,
        'payé': 100,
        'rejeté': 0
    }
    progress_percentage = progress_mapping.get(mandat.statut.value, 0)
    
    # Historique des événements (à adapter selon votre modèle)
    historique = []  # Récupérer l'historique depuis votre modèle
    
    return render_template('user_agent/suivi_mandat.html',
                         mandat=mandat,
                         jours_restants=jours_restants,
                         progress_percentage=progress_percentage,
                         historique=historique,
                         today=datetime.now().date())

@app.route('/mandats/detail/<int:mandat_id>')
@login_required
def mandat_detail(mandat_id):
    """Détail d'un mandat."""
    mandat = Mandat.query.get_or_404(mandat_id)
    today = datetime.utcnow().date()

    
    # Vérification des permissions
    if current_user.role not in [UserRole.ADMIN, UserRole.TRESORIER]:
        if mandat.agent_id != current_user.id and mandat.fournisseur_id != current_user.id:
            flash('Accès non autorisé', 'danger')
            return redirect(url_for('dashboard'))
    
    # Récupérer l'historique du mandat
    historiques = HistoriqueMandat.query.filter_by(mandat_id=mandat_id)\
        .order_by(HistoriqueMandat.date_action.desc())\
        .all()
    
    # --- Corrected Logic for Date Calculation ---
    from datetime import date
    
    duree = 0
    jours_restants = 0
    today_date_only = date.today()
    
    if mandat.date_depot:
        # Convert date_depot to a date-only object for calculation
        date_depot_as_date = mandat.date_depot.date()
        duree = (today_date_only - date_depot_as_date).days
        
    if mandat.date_echeance:
        jours_restants = (mandat.date_echeance - today_date_only).days
    
    # --- End of Corrected Logic ---
    
    # Choose the correct template based on user role
    elif current_user.role == UserRole.FOURNISSEUR:

        return render_template('user_fournisseur/mandat_detail_fournisseur.html', 
                             mandat=mandat, 
                             historiques=historiques,
                             duree=duree,
                             jours_restants=jours_restants,
                             today=today
                             )
    
    else:
        return render_template('user_agent/mandat_detail.html', 
                             mandat=mandat, 
                             historiques=historiques,
                             duree=duree,
                             jours_restants=jours_restants,
                             today=today)

# ============================================================================
# TRÉSORERIE - TRAITEMENT DES MANDATS
# ============================================================================

@app.route('/tresorerie/mandats')
@login_required
def mandats_a_traiter():
    """Liste des mandats à traiter (Trésorier/Admin seulement) avec pagination."""
    if current_user.role not in [UserRole.TRESORIER, UserRole.ADMIN]:
        flash('Accès réservé au trésor', 'danger')
        # return redirect(url_for('dashboard'))
    
    # 1. Obtenir les paramètres de pagination depuis l'URL
    page = request.args.get('page', 1, type=int)
    per_page = 10 # Nombre d'éléments par page

    statut = request.args.get('statut', 'en_cours')
    try:
        # 2. Utiliser .paginate() à la place de .all()
        mandats = db.paginate(
            db.select(Mandat).filter_by(statut=StatutMandat(statut)).order_by(Mandat.date_depot.asc()),
            page=page,
            per_page=per_page
        )
    except ValueError:
        # Gestion de l'erreur si le statut n'est pas valide
        mandats = db.paginate(
            db.select(Mandat).filter_by(statut=StatutMandat.EN_COURS).order_by(Mandat.date_depot.asc()),
            page=page,
            per_page=per_page
        )
        statut = 'en_cours'
    
    return render_template('user_agent/mandats_a_traiter.html', mandats=mandats, statut=statut)


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
        
        if action == 'valider':
            mandat.date_validation = datetime.utcnow()
        elif action == 'payer':
            mandat.date_paiement = datetime.utcnow()
        
        historique = HistoriqueMandat(
            mandat_id=mandat.id,
            action=message_action,
            service=current_user.service or "Trésor",
            commentaire=commentaire,
            user_id=current_user.id
        )
        db.session.add(historique)
        
        notification_message = f"Mandat {mandat.reference} : {message_action}"
        for user_id in [mandat.agent_id, mandat.fournisseur_id]:
            notification = Notification(
                user_id=user_id,
                message=notification_message,
                type_notification="success" if action in ['valider', 'payer'] else "warning"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash(f'Mandat {message_action.lower()} avec succès', 'success')
    else:
        flash('Action non reconnue', 'danger')
    
    # La redirection correcte est ici, vers la page qui liste les mandats
    return redirect(url_for('mandats_a_traiter'))

def get_statut_color(statut):
    """Retourne une couleur associée à un statut pour l'affichage."""
    color_mapping = {
        StatutMandat.DEPOSE: 'gray',
        StatutMandat.EN_COURS: 'orange',
        StatutMandat.VALIDE: 'green',
        StatutMandat.PRET_A_PAYER: 'purple',
        StatutMandat.PAYE: 'teal',
        StatutMandat.REJETE: 'red'
    }
    return color_mapping.get(statut, 'black')

@app.route('/agent/mandats')
@login_required
def liste_mandats():
    """Liste des mandats de l'agent avec pagination et filtres"""
    if current_user.role not in [UserRole.AGENT, UserRole.ADMIN]:
        flash('Accès réservé aux agents', 'danger')
        return redirect(url_for('dashboard'))
    
    # Récupération des paramètres de filtrage
    page = request.args.get('page', 1, type=int)
    statut_filter = request.args.get('statut')
    fournisseur_id = request.args.get('fournisseur_id', type=int)
    date_debut = request.args.get('date_debut')
    date_fin = request.args.get('date_fin')
    
    # Construction de la requête de base
    query = Mandat.query.filter_by(agent_id=current_user.id)
    
    # Application des filtres
    filtres_actifs = []
    
    if statut_filter:
        try:
            statut = StatutMandat[statut_filter.upper()]
            query = query.filter_by(statut=statut)
            filtres_actifs.append(f"Statut: {statut.value}")
        except KeyError:
            pass
    
    if fournisseur_id:
        query = query.filter_by(fournisseur_id=fournisseur_id)
        fournisseur = fournisseurs = User.query.filter_by(role=UserRole.FOURNISSEUR).all()

        if fournisseur:
            filtres_actifs.append(f"Fournisseur: {fournisseur.nom}")
    
    if date_debut:
        try:
            date_debut_obj = datetime.strptime(date_debut, '%Y-%m-%d')
            query = query.filter(Mandat.date_depot >= date_debut_obj)
            filtres_actifs.append(f"À partir du: {date_debut_obj.strftime('%d/%m/%Y')}")
        except ValueError:
            pass
    
    if date_fin:
        try:
            date_fin_obj = datetime.strptime(date_fin, '%Y-%m-%d')
            query = query.filter(Mandat.date_depot <= date_fin_obj)
            filtres_actifs.append(f"Jusqu'au: {date_fin_obj.strftime('%d/%m/%Y')}")
        except ValueError:
            pass
    
    # Pagination
    mandats = query.order_by(Mandat.date_depot.desc()).paginate(
        page=page, 
        per_page=10, 
        error_out=False
    )
    
    # Statistiques pour les filtres appliqués
    stats_filtrees = []
    tous_statuts = StatutMandat
    for statut in tous_statuts:
        count = query.filter_by(statut=statut).count()
        if count > 0:
            stats_filtrees.append({
                'nom': statut.value,
                'count': count,
                'color': get_statut_color(statut)
            })
    
    # Liste des fournisseurs pour le filtre
    fournisseurs = User.query.filter(
    User.role == UserRole.FOURNISSEUR,
    User.mandats_fournisseur.any(agent_id=current_user.id)
).distinct().all()
    
    return render_template('user_agent/liste_mandats.html',
                         mandats=mandats,
                         stats_filtrees=stats_filtrees,
                         filtres_actifs=filtres_actifs,
                         fournisseurs=fournisseurs,
                         tous_statuts=tous_statuts)


@app.route('/agent/mandat/<int:mandat_id>/modifier', methods=['GET', 'POST'])
@login_required
def modifier_mandat(mandat_id):
    """Modifier un mandat existant"""
    mandat = Mandat.query.get_or_404(mandat_id)
    
    # Vérification des permissions
    if mandat.agent_id != current_user.id:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('liste_mandats'))
    
    # Vérification que le mandat peut être modifié
    if mandat.statut not in [StatutMandat.EN_ATTENTE, StatutMandat.EN_COURS]:
        flash('Ce mandat ne peut plus être modifié', 'warning')
        return redirect(url_for('detail_mandat', mandat_id=mandat.id))
    
    if request.method == 'POST':
        try:
            # Mise à jour des données
            mandat.montant = float(request.form.get('montant', 0))
            mandat.montant_ht = float(request.form.get('montant_ht', 0)) or None
            mandat.description = request.form.get('description', '')
            mandat.date_echeance = datetime.strptime(request.form.get('date_echeance'), '%Y-%m-%d')
            mandat.urgence = bool(request.form.get('urgence'))
            
            # Historique
            historique = HistoriqueMandat(
                mandat_id=mandat.id,
                action="Modification du mandat",
                service=current_user.service or "Agent",
                commentaire=request.form.get('commentaire_modification', ''),
                user_id=current_user.id
            )
            db.session.add(historique)
            
            db.session.commit()
            flash('Mandat modifié avec succès', 'success')
            return redirect(url_for('detail_mandat', mandat_id=mandat.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la modification: {str(e)}', 'danger')
    
    fournisseurs = Fournisseur.query.all()
    return render_template('user_agent/modifier_mandat.html', 
                         mandat=mandat, 
                         fournisseurs=fournisseurs)

@app.route('/agent/mandat/<int:mandat_id>/corriger', methods=['GET', 'POST'])
@login_required
def corriger_mandat(mandat_id):
    """Corriger un mandat après demande de correction"""
    mandat = Mandat.query.get_or_404(mandat_id)
    
    if mandat.agent_id != current_user.id:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('liste_mandats'))
    
    if not mandat.correction_requise:
        flash('Aucune correction requise pour ce mandat', 'info')
        return redirect(url_for('detail_mandat', mandat_id=mandat.id))
    
    if request.method == 'POST':
        try:
            # Application des corrections
            mandat.montant = float(request.form.get('montant', 0))
            mandat.description = request.form.get('description', '')
            mandat.correction_requise = False
            mandat.statut = StatutMandat.EN_ATTENTE  # Retour en attente après correction
            
            # Historique
            historique = HistoriqueMandat(
                mandat_id=mandat.id,
                action="Correction appliquée",
                service=current_user.service or "Agent",
                commentaire=request.form.get('commentaire_correction', ''),
                user_id=current_user.id
            )
            db.session.add(historique)
            
            # Notification aux trésoriers
            tresoriers = User.query.filter(User.role.in_([UserRole.TRESORIER, UserRole.ADMIN])).all()
            for tresorier in tresoriers:
                notification = Notification(
                    user_id=tresorier.id,
                    message=f"Mandat {mandat.reference} corrigé",
                    type_notification="info"
                )
                db.session.add(notification)
            
            db.session.commit()
            flash('Correction appliquée avec succès', 'success')
            return redirect(url_for('detail_mandat', mandat_id=mandat.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la correction: {str(e)}', 'danger')
    
    return render_template('user_agent/corriger_mandat.html', mandat=mandat)

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
    # Récupérer les statistiques selon le rôle
    if current_user.role == UserRole.AGENT:
        stats = {
            'mandats_total': Mandat.query.filter_by(agent_id=current_user.id).count(),
            'mandats_en_cours': Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.EN_COURS).count(),
            'mandats_valides': Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.VALIDE).count(),
            'mandats_payes': Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.PAYE).count()
        }
        
        # Activités récentes (derniers mandats déposés)
        mandats_recents = Mandat.query.filter_by(agent_id=current_user.id)\
            .order_by(Mandat.date_depot.desc())\
            .limit(5)\
            .all()
        
        # Transformer en format pour l'activité
        activites_recentes = []
        for mandat in mandats_recents:
            activites_recentes.append({
                'action': f'Mandat {mandat.reference} déposé',
                'description': f'Montant: {mandat.montant} FCFA - {mandat.fournisseur.nom_complet if mandat.fournisseur else "Fournisseur inconnu"}',
                'date': mandat.date_depot,
                'type': 'Mandat'
            })
        
        return render_template('user_agent/agent_profile.html', 
                             stats=stats, 
                             activites_recentes=activites_recentes)
    
    elif current_user.role == UserRole.FOURNISSEUR:
        # Statistiques pour fournisseur
        mandats_total = Mandat.query.filter_by(fournisseur_id=current_user.id).count()
        mandats_payes_query = Mandat.query.filter_by(
            fournisseur_id=current_user.id, 
            statut=StatutMandat.PAYE
        ).all()
        
        stats = {
            'mandats_total': mandats_total,
            'mandats_attente': Mandat.query.filter_by(
                fournisseur_id=current_user.id, 
                statut=StatutMandat.EN_COURS
            ).count(),
            'mandats_payes': len(mandats_payes_query),
            'montant_total': sum(mandat.montant for mandat in mandats_payes_query)
        }
        
        return render_template('user_fournisseur/fournisseur_profile.html', stats=stats)
    
    else:
        # Pour admin/trésorier - template simplifié
        return render_template('user_agent/agent_profile.html', 
                             stats={'mandats_total': 0, 'mandats_en_cours': 0, 'mandats_valides': 0, 'mandats_payes': 0},
                             activites_recentes=[])


@app.route('/statistiques')
@login_required
def statistiques():
    """Page de statistiques"""
    if current_user.role == UserRole.AGENT:
        # Statistiques de base
        mandats_total = Mandat.query.filter_by(agent_id=current_user.id).count()
        mandats_valides = Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.VALIDE).count()
        mandats_payes = Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.PAYE).count()
        mandats_en_cours = Mandat.query.filter_by(agent_id=current_user.id, statut=StatutMandat.EN_COURS).count()
        
        # Calcul du montant total
        mandats_agent = Mandat.query.filter_by(agent_id=current_user.id).all()
        montant_total = sum(mandat.montant for mandat in mandats_agent)
        
        # Calcul des taux et métriques
        taux_validation = round((mandats_valides / mandats_total * 100), 1) if mandats_total > 0 else 0
        moyenne_mandat = round(montant_total / mandats_total, 2) if mandats_total > 0 else 0
        
        # Objectifs (valeurs simulées - à adapter)
        objectif_mandats = 50
        objectif_montant = 5000000
        objectif_validation = 80
        
        objectif_mandats_progress = round((mandats_total / objectif_mandats * 100), 1) if objectif_mandats > 0 else 0
        objectif_montant_progress = round((montant_total / objectif_montant * 100), 1) if objectif_montant > 0 else 0
        
        # Top 5 des mandats
        top_mandats = Mandat.query.filter_by(agent_id=current_user.id)\
            .order_by(Mandat.montant.desc())\
            .limit(5)\
            .all()
        
        # Performance par statut
        performance_statuts = [
            {'nom': 'Déposés', 'nombre': mandats_total, 'pourcentage': 100, 'icon': 'upload', 'color': 'primary'},
            {'nom': 'Validés', 'nombre': mandats_valides, 'pourcentage': taux_validation, 'icon': 'check-circle', 'color': 'success'},
            {'nom': 'En Cours', 'nombre': mandats_en_cours, 'pourcentage': round((mandats_en_cours / 1 + mandats_total * 100), 1), 'icon': 'clock', 'color': 'warning'},
            {'nom': 'Payés', 'nombre': mandats_payes, 'pourcentage': round((mandats_payes / 1 + mandats_total * 100), 1), 'icon': 'money-bill-wave', 'color': 'info'}
        ]
        
        # Données pour graphiques (simulées)
        dates_depots = ['Sem 1', 'Sem 2', 'Sem 3', 'Sem 4']
        valeurs_depots = [12, 18, 15, 22]
        
        # Fournisseurs les plus utilisés
        fournisseurs_data = {}
        for mandat in mandats_agent:
            if mandat.fournisseur:
                nom = mandat.fournisseur.nom_complet
                fournisseurs_data[nom] = fournisseurs_data.get(nom, 0) + 1
        
        labels_fournisseurs = list(fournisseurs_data.keys())[:5]
        valeurs_fournisseurs = list(fournisseurs_data.values())[:5]
        
        stats = {
            'mandats_total': mandats_total,
            'mandats_valides': mandats_valides,
            'mandats_payes': mandats_payes,
            'montant_total': montant_total,
            'taux_validation': taux_validation,
            'moyenne_mandat': moyenne_mandat,
            'evolution_depots': 15.5,  # Simulation
            'score_performance': 8.2,  # Simulation
            'classement': 3,  # Simulation
            'total_agents': 25,  # Simulation
            'objectif_mandats': objectif_mandats,
            'objectif_montant': objectif_montant,
            'objectif_validation': objectif_validation,
            'objectif_mandats_progress': objectif_mandats_progress,
            'objectif_montant_progress': objectif_montant_progress
        }
        
        return render_template('user_agent/agent_statistiques.html',
                             stats=stats,
                             top_mandats=top_mandats,
                             performance_statuts=performance_statuts,
                             dates_depots=dates_depots,
                             valeurs_depots=valeurs_depots,
                             labels_fournisseurs=labels_fournisseurs,
                             valeurs_fournisseurs=valeurs_fournisseurs,
                             activites_recentes=[])  # À implémenter
    elif current_user.role == UserRole.FOURNISSEUR:
        # Calcul des statistiques de base
        mandats_total = Mandat.query.filter_by(fournisseur_id=current_user.id).count()
        mandats_payes_query = Mandat.query.filter_by(
            fournisseur_id=current_user.id, 
            statut=StatutMandat.PAYE
        ).all()
        mandats_attente = Mandat.query.filter_by(
            fournisseur_id=current_user.id, 
            statut=StatutMandat.EN_COURS
        ).count()
        
        montant_total = sum(mandat.montant for mandat in mandats_payes_query)
        mandats_payes = len(mandats_payes_query)
        
        # Calcul des taux
        taux_paiement = round((mandats_payes / mandats_total * 100), 2) if mandats_total > 0 else 0
        taux_attente = round((mandats_attente / mandats_total * 100), 2) if mandats_total > 0 else 0
        moyenne_mandat = round(montant_total / mandats_payes, 2) if mandats_payes > 0 else 0
        
        # Top 5 des mandats par montant
        top_mandats = Mandat.query.filter_by(fournisseur_id=current_user.id)\
            .order_by(Mandat.montant.desc())\
            .limit(5)\
            .all()
        
        # Données pour les graphiques (simulées - à adapter avec vos données réelles)
        dates_ca = ['Jan', 'Fév', 'Mar', 'Avr', 'Mai', 'Jun']
        valeurs_ca = [250000, 320000, 280000, 410000, 380000, 450000]
        
        labels_statut = ['Payés', 'En attente', 'Validés', 'Rejetés']
        valeurs_statut = [mandats_payes, mandats_attente, 15, 2]  # Valeurs simulées
        
        stats = {
            'montant_total': montant_total,
            'mandats_payes': mandats_payes,
            'mandats_attente': mandats_attente,
            'mandats_total': mandats_total,
            'taux_paiement': taux_paiement,
            'taux_attente': taux_attente,
            'moyenne_mandat': moyenne_mandat,
            'evolution_montant': 12.5  # Simulation
        }
        
        return render_template('user_fournisseur/fournisseur_statistiques.html',
                             stats=stats,
                             top_mandats=top_mandats,
                             dates_ca=dates_ca,
                             valeurs_ca=valeurs_ca,
                             labels_statut=labels_statut,
                             valeurs_statut=valeurs_statut,
                             performance_mensuelle=[],  # À implémenter
                             timeline=[])  # À implémenter
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