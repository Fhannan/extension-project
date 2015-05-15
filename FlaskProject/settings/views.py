# -*- coding: utf-8 -*-

import os
import hashlib

from datetime import datetime

from flask import *
from flask.ext.login import login_required, current_user

from ..extensions import db,mail
from ..user import Group, user_datastore, Invitations, Category, User, Link
from .forms import UpdateProfileForm, InviteUserForm
from flask.ext.mail import Message
import pprint

settings = Blueprint('settings', __name__, url_prefix='/settings')

@settings.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    user = user_datastore.get_user(current_user.id)
    form = UpdateProfileForm(request.form, obj=user)
    if request.method == 'POST' and form.validate() and current_user.is_authenticated():
        form.populate_obj(user)
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        db.session.commit()
        flash('your data has been updated','success')
        # return redirect(url_for('frontend.index'))
    return render_template('settings/profile_update.html', form=form)

@settings.route('/user_invite', methods=['GET', 'POST'])
def user_invite():

    my_group = Group.query.filter(Group.owner_id == current_user.id).first()
    form = InviteUserForm(request.form)
    if request.method == 'POST' and form.validate() and current_user.is_authenticated():
        email = request.form['email']
        i = Invitations(email = email, invitation_date = datetime.utcnow(), invited_by = current_user.id, accepted = 0)
        db.session.add(i)
        db.session.commit()
        inv = Invitations.query.filter(Invitations.email == email).first()
        url = 'http://staging.ivivelabs.com:3104?inv={0}&grp_id={1}&inv_id={2}'.format(1,my_group.id,inv.id)
        message = Message("Hello",
            body = "you are invited. please click into that link below",
            html = "you are invited to join the group of flask extension project. please click into that link below <br> <a href = {0}>click here to join </a>".format(url),
            sender = current_app.config['MAIL_USERNAME'],
            recipients = [email])
        mail.send(message)
        flash('An email has been sent to that email address to make the person join into your group','success')
        # return redirect(url_for('frontend.index'))"""
    return render_template('settings/user_invite.html', form=form)



