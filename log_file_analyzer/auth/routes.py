from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from .utils import send_otp_email
import random

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']

        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['email'] = email

        send_otp_email(email, otp)
        flash('OTP sent to your email.', 'info')
        return redirect(url_for('auth.verify_otp'))

    return render_template('auth/login.html')

@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP.', 'danger')
            return redirect(url_for('auth.verify_otp'))

    return render_template('auth/verify_otp.html')
