# =====================================
# services/subscription_service.py - Subscription logic
# =====================================

import stripe
from datetime import datetime, timedelta
from models import User
from app import db
from config import Config

stripe.api_key = Config.STRIPE_SECRET_KEY

class SubscriptionService:
    
    @staticmethod
    def create_stripe_customer(user):
        """Create a Stripe customer for the user"""
        customer = stripe.Customer.create(
            email=user.email,
            name=user.username,
            metadata={'user_id': user.id}
        )
        
        user.stripe_customer_id = customer.id
        db.session.commit()
        
        return customer
    
    @staticmethod
    def create_payment_intent(user, plan):
        """Create a payment intent for subscription"""
        if plan not in Config.SUBSCRIPTION_PLANS:
            raise ValueError("Invalid subscription plan")
        
        plan_info = Config.SUBSCRIPTION_PLANS[plan]
        
        # Ensure user has Stripe customer ID
        if not user.stripe_customer_id:
            SubscriptionService.create_stripe_customer(user)
        
        intent = stripe.PaymentIntent.create(
            amount=plan_info['price'],
            currency='usd',
            customer=user.stripe_customer_id,
            metadata={
                'plan': plan,
                'user_id': user.id
            }
        )
        
        return intent
    
    @staticmethod
    def upgrade_subscription(user, plan):
        """Upgrade user subscription"""
        user.subscription_plan = plan
        user.subscription_end = datetime.utcnow() + timedelta(days=30)
        db.session.commit()
    
    @staticmethod
    def cancel_subscription(user):
        """Cancel user subscription"""
        user.subscription_plan = 'free'
        user.subscription_end = None
        db.session.commit()