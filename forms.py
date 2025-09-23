from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FloatField, SelectField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange
from wtforms.validators import ValidationError
from models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

class OTPForm(FlaskForm):
    otp_code = StringField('Code OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Vérifier')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='L\'email est requis'),
        Email(message='Format d\'email invalide')
    ])
    telephone = StringField('Téléphone', validators=[
        DataRequired(message='Le téléphone est requis'),
        Length(min=10, message='Numéro de téléphone invalide')
    ])
    nom_complet = StringField('Nom complet', validators=[
        DataRequired(message='Le nom complet est requis'),
        Length(min=2, max=200, message='Le nom doit contenir entre 2 et 200 caractères')
    ])
    password = PasswordField('Mot de passe', validators=[
        DataRequired(message='Le mot de passe est requis'),
        Length(min=6, message='Le mot de passe doit contenir au moins 6 caractères'),
        EqualTo('confirm_password', message='Les mots de passe doivent correspondre')
    ])
    confirm_password = PasswordField('Confirmer le mot de passe')
    role = SelectField('Rôle', choices=[
        ('', 'Sélectionnez votre rôle'),
        ('agent', 'Agent'),
        ('fournisseur', 'Fournisseur'),
        ('tresorier', 'Trésorier')
    ], validators=[DataRequired(message='Veuillez sélectionner un rôle')])
    entreprise = StringField('Entreprise', validators=[
        Length(max=200, message='Le nom de l\'entreprise ne doit pas dépasser 200 caractères')
    ])
    service = StringField('Service', validators=[
        Length(max=200, message='Le nom du service ne doit pas dépasser 200 caractères')
    ])

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Un compte avec cet email existe déjà.')
            

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='L\'email est requis'),
        Email(message='Format d\'email invalide')
    ])

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nouveau mot de passe', validators=[
        DataRequired(message='Le mot de passe est requis'),
        Length(min=6, message='Le mot de passe doit contenir au moins 6 caractères'),
        EqualTo('confirm_password', message='Les mots de passe doivent correspondre')
    ])
    confirm_password = PasswordField('Confirmer le nouveau mot de passe')
    submit = SubmitField('Réinitialiser le mot de passe')


class MandatForm(FlaskForm):
    reference = StringField('Référence du mandat', validators=[DataRequired(), Length(max=50)])
    montant = FloatField('Montant', validators=[DataRequired(), NumberRange(min=0.01)])
    description = TextAreaField('Description', validators=[DataRequired()])
    fournisseur_id = SelectField('Fournisseur', coerce=int, validators=[DataRequired()])
    fichier = FileField('Fichier du mandat')
    submit = SubmitField('Déposer le mandat')

class TraitementMandatForm(FlaskForm):
    action = SelectField('Action', choices=[
        ('valider', 'Valider'),
        ('rejeter', 'Rejeter'),
        ('pret_a_payer', 'Prêt à payer'),
        ('payer', 'Payer')
    ], validators=[DataRequired()])
    commentaire = TextAreaField('Commentaire')
    submit = SubmitField('Appliquer')