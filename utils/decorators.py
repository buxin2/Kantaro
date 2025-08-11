# =====================================
# utils/decorators.py - Custom decorators
# =====================================

from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

def subscription_required(f):
    """Decorator to check if user has active subscription"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_subscription_active:
            flash('Your subscription has expired. Please upgrade your plan.', 'warning')
            return redirect(url_for('subscription.pricing'))
        return f(*args, **kwargs)
    return decorated_function

def camera_limit_check(f):
    """Decorator to check camera limits"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.can_add_camera():
            flash(f'You have reached your camera limit ({current_user.camera_limit}). Please upgrade your plan.', 'warning')
            return redirect(url_for('subscription.pricing'))
        return f(*args, **kwargs)
    return decorated_function