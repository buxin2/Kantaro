# =====================================
# routes/subscription.py - Subscription routes
# =====================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from services.subscription_service import SubscriptionService
from config import Config
import stripe

subscription_bp = Blueprint('subscription', __name__, url_prefix='/subscription')

@subscription_bp.route('/pricing')
def pricing():
    return render_template('subscription/pricing.html', 
                         stripe_public_key=Config.STRIPE_PUBLISHABLE_KEY,
                         plans=Config.SUBSCRIPTION_PLANS)

@subscription_bp.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment():
    try:
        data = request.get_json()
        plan = data.get('plan')
        
        intent = SubscriptionService.create_payment_intent(current_user, plan)
        
        return jsonify({
            'client_secret': intent.client_secret
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@subscription_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, Config.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400
    
    # Handle successful payment
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        user_id = payment_intent['metadata']['user_id']
        plan = payment_intent['metadata']['plan']
        
        user = User.query.get(user_id)
        if user:
            SubscriptionService.upgrade_subscription(user, plan)
    
    return 'Success', 200