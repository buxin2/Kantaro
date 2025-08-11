# =====================================
# config.py - Configuration settings
# =====================================

import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///security_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Stripe Configuration
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY') or 'sk_test_your_stripe_secret_key'
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY') or 'pk_test_your_stripe_publishable_key'
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET') or 'whsec_your_webhook_secret'
    
    # Subscription Plans
    SUBSCRIPTION_PLANS = {
        'free': {'price': 0, 'cameras': 1, 'name': 'Free'},
        'basic': {'price': 999, 'cameras': 1, 'name': 'Basic'},  # $9.99 in cents
        'pro': {'price': 1999, 'cameras': 4, 'name': 'Pro'},    # $19.99 in cents
        'business': {'price': 4999, 'cameras': 10, 'name': 'Business'}  # $49.99 in cents
    }
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True

class ProductionConfig(Config):
    DEBUG = False
    # Add production-specific settings here