# =====================================
# routes/main.py - Main routes
# =====================================

from flask import Blueprint, render_template
from flask_login import current_user

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return render_template('home.html')

@main_bp.route('/about')
def about():
    return render_template('about.html')