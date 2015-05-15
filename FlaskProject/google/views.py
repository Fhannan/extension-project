# -*- coding: utf-8 -*-

import os

from flask import *
import flask.ext.restless
from ..user import User, db, user_datastore, Group, Invitations
from ..utils import password_generator
from rauth.service import OAuth2Service
from datetime import datetime
import pprint
googs = Blueprint('googs', __name__, url_prefix='/googs')


google = OAuth2Service(
    client_id='1031527430352-25s0d7nb6u7t172gmfjrifpk6kn7j9t2',
    client_secret='369PTHK84bHbnSbGdvgdzk1Y',
    name='google',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    base_url='https://accounts.google.com/o/oauth2/auth',
)

def reg_or_login(provider, email, provider_id, screen_name, provider_access_token):
    find_user = user_datastore.find_user(provider_id = provider_id)
    if find_user:
        #user_datastore.activate_user(user)
        flask.ext.security.utils.login_user(find_user)
        flash('Logged in as ' + screen_name,'info')
        return redirect(url_for('frontend.index'))
    if (find_user is None) and (not 'group_id' in flask.session):
        if User.query.filter(User.email == email).count() > 0:
            flash('this email  ' + email + '  is already associated with another account','warning')
            return redirect(url_for('frontend.index'))
        else:
            user = user_datastore.create_user(confirmed_at = datetime.utcnow(),\
                                          provider = provider,\
                                          email = email,\
                                          provider_id = provider_id,\
                                          password = flask.ext.security.utils.encrypt_password(password_generator(8)),\
                                          provider_access_token = provider_access_token )
            db.session.add(user)
            db.session.commit()
            # group creation for not-invited user after registration
            u = user_datastore.get_user(email)
            g = Group(is_admin=True, group_creation_date = datetime.utcnow(), owner_id = u.id)
            u.groups.append(g)
            db.session.commit()
            flask.ext.security.utils.login_user(user)
            flash('You are now registered in this program','info')
            flash('Logged in as ' +email, 'info')
            return redirect(url_for('frontend.index'))
    #group creation and group joining for invited user who is not registered
    if (find_user is None) and ('group_id' in flask.session):
        i = Invitations.query.filter(Invitations.id == flask.session['inv_id']).first()
        user = user_datastore.create_user(confirmed_at = datetime.utcnow(),\
                                                email = i.email,\
                                                provider = provider,\
                                                provider_id = provider_id,\
                                                password = flask.ext.security.utils.encrypt_password(password_generator(8)),\
                                                provider_access_token = provider_access_token)
        db.session.add(user)
        db.session.commit()
        u = user_datastore.get_user(i.email)
        # create a group for that new user
        g_add = Group(is_admin=True, group_creation_date = datetime.utcnow(), owner_id = u.id)
        u.groups.append(g_add)
        # joining to that invited group
        g = Group.query.filter(Group.id == flask.session['group_id']).first()
        g.users.append(u)
        i.accepted = True
        db.session.commit()

        # person who has invited also will join to the group of the person who got invitation
        g_who_got_invitation=Group.query.filter(Group.owner_id == u.id).first()
        # user instance who has invited
        usr_who_has_invited = User.query.filter(User.id == g.owner_id).first()
        g_who_got_invitation.users.append(usr_who_has_invited)
        db.session.commit()
        flask.session.pop('group_id', None)
        flask.session.pop('inv_id', None)
        flask.ext.security.utils.login_user(user)
        flash('You are now registered in this program','info')
        flash('You are added to the group', 'info')
        flash('Logged in as ' +i.email, 'info')
        return redirect(url_for('frontend.index'))

@googs.route('/login')
def login():
    flask.session.pop('group_id', None)
    flask.session.pop('inv_id', None)
    if not 'grp_id' in request.args:
        redirect_uri = url_for('googs.authorized', _external=True)
    if 'grp_id' in request.args:
        grp_id = request.args.get('grp_id')
        inv_id = request.args.get('inv_id')
        flask.session['group_id'] = grp_id
        flask.session['inv_id'] = inv_id
        e = Invitations.query.filter(Invitations.id == inv_id).first()
        usr = user_datastore.get_user(e.email)
        # invited user who is already registered.so he has already a group.so he will be added to the invited group
        if usr and e.accepted == False:
            g = Group.query.filter(Group.id == grp_id).first()
            g.users.append(usr)
            e.accepted = True
            db.session.commit()
            # person who has invited also will join to the group of the person who got invitation
            g_who_got_invitation=Group.query.filter(Group.owner_id == usr.id).first()
            # user instance who has invited
            usr_who_has_invited = User.query.filter(User.id == g.owner_id).first()
            g_who_got_invitation.users.append(usr_who_has_invited)
            db.session.commit()
            flask.ext.security.utils.login_user(usr)
            flash('you are already registerd in this program','info')
            flash('you are added to the group' +grp_id,'info')
            flash('Logged in as ' + e.email,'info')
            return redirect(url_for('frontend.index'))
        redirect_uri = url_for('googs.authorized', _external=True)
        #redirect_uri = 'http://staging.ivivelabs.com:3104/googs/authorized?def={0}'.format(p)
    params = {'scope':'email profile',
              'response_type':'code',
        'redirect_uri': redirect_uri}
    return redirect(google.get_authorize_url(**params))

@googs.route('/authorized')
def authorized():
    pprint.pprint(request.args.get('def'))
    if not 'code' in request.args:
         flash('You did not authorize the request','info')
         return redirect(url_for('frontend.index'))

    redirect_uri = url_for('googs.authorized', _external=True)
    code = request.args['code']
    session = google.get_auth_session(
        data=dict(
            code=code,
            redirect_uri=redirect_uri,
            grant_type='authorization_code'
        ),
        decoder=json.loads
    )
    json_path = 'https://www.googleapis.com/oauth2/v1/userinfo'
    session_json = session.get(json_path).json()
    # For non-Ascii characters to work properly!
    session_json = dict((k, unicode(v).encode('utf-8')) for k, v in session_json.iteritems())
    reg_or_login('google', session_json['email'], session_json['id'], session_json['name'], session.access_token )

    return redirect(url_for('frontend.index'))

