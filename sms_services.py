import os
import logging
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from datetime import datetime, timedelta
import random
import string

class SMSService:
    def __init__(self):
        self.account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
        self.auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
        self.phone_number = os.environ.get('TWILIO_PHONE_NUMBER')
        self.client = Client(self.account_sid, self.auth_token)
        self.logger = logging.getLogger(__name__)

    def generate_otp(self, length=6):
        """Génère un OTP numérique"""
        return ''.join(random.choices(string.digits, k=length))

    def send_otp_sms(self, phone_number, otp_code):
        """
        Envoie un OTP par SMS via Twilio
        """
        try:
            message = self.client.messages.create(
                body=f"Votre code de vérification MandatPro est : {otp_code}. Valable 10 minutes.",
                from_=self.phone_number,
                to=phone_number
            )
            
            self.logger.info(f"SMS OTP envoyé à {phone_number}. SID: {message.sid}")
            return {
                'success': True,
                'message_sid': message.sid,
                'status': message.status
            }
            
        except TwilioRestException as e:
            self.logger.error(f"Erreur Twilio pour {phone_number}: {e}")
            return {
                'success': False,
                'error': str(e),
                'code': e.code
            }
        except Exception as e:
            self.logger.error(f"Erreur générale SMS pour {phone_number}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def validate_phone_number(self, phone_number):
        """
        Valide un numéro de téléphone avec Twilio Lookup
        """
        try:
            phone_number = self.client.lookups \
                .v1 \
                .phone_numbers(phone_number) \
                .fetch(type=['carrier'])
            
            return {
                'valid': True,
                'formatted': phone_number.phone_number,
                'carrier': phone_number.carrier
            }
        except TwilioRestException as e:
            return {
                'valid': False,
                'error': str(e)
            }

# Instance globale du service
sms_service = SMSService()