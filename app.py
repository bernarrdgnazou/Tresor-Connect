from flask import Flask, render_template, request, flash, redirect, url_for, session
import os


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key_for_development')

# Routes françaises
@app.route('/index')
def home():
    return render_template('index.html')

@app.route('/fonction')
def fonction():
    return render_template('fonction.html')

@app.route('/traitement')
def traitement():
    return render_template('traitement.html')

@app.route('/faq')
def faq():
    return render_template('faq.html',)

# @app.route('/fr/contact', methods=['GET', 'POST'])
# def fr_contact():
#     if request.method == 'POST':
#         return render_template('contact.html', 'fr')


if __name__ == '__main__':
    app.run(debug=True)