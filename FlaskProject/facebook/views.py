# -*- coding: utf-8 -*-

import os
from flask import *
import flask.ext.restless
from ..user import User, Getemail, db, user_datastore, Group, Invitations
from ..utils import password_generator
from rauth.service import OAuth2Service
from flask.ext.login import current_user
from datetime import datetime
import pprint


fbook = Blueprint('fbook', __name__, url_prefix='/fbook')

graph_url = 'https://graph.facebook.com/'
facebook = OAuth2Service(name='facebook',
                         authorize_url='https://www.facebook.com/dialog/oauth',
                         access_token_url=graph_url + 'oauth/access_token',
                         client_id='1410369132585882',
                         client_secret='6f200e2a3b933c8567d7fdcd19620f2e',
                         base_url=graph_url)

@fbook.route('/login')
def login():
    flask.session.pop('group_id', None)
    flask.session.pop('inv_id', None)
    if not 'grp_id' in request.args:
        redirect_uri = url_for('fbook.authorized', _external=True)
    if 'grp_id' in request.args:
        grp_id = request.args.get('grp_id')
        inv_id = request.args.get('inv_id')
        e = Invitations.query.filter(Invitations.id == inv_id).first()
        usr = user_datastore.find_user(email = e.email)
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
        else:
            redirect_uri = 'http://staging.ivivelabs.com:3104/fbook/authorized?grp_id={0}&inv_id={1}'.format(grp_id,inv_id)
    params = {'scope':'email',
                'scope':'public_profile',
                'redirect_uri': redirect_uri}
    return redirect(facebook.get_authorize_url(**params))


@fbook.route('/authorized',methods=['GET','POST'])
def authorized():
    grp_id = None
    if not 'code' in request.args:
        flash('You did not authorize the request','danger')
        return redirect(url_for('frontend.index'))
        #make a request for the access token credentials using code
    if 'code' and 'grp_id' in request.args:
        grp_id = request.args.get('grp_id')
        inv_id = request.args.get('inv_id')

        redirect_uri = 'http://staging.ivivelabs.com:3104/fbook/authorized?grp_id={0}&inv_id={1}'.format(grp_id,inv_id)
    else:
        redirect_uri = url_for('fbook.authorized', _external=True)
    data = dict(code=request.args['code'], grant_type='authorization_code', redirect_uri=redirect_uri)
    session = facebook.get_auth_session(data=data)
    # the "me" response
    me = session.get('me').json()
    provider_id = me['id']
    provider_access_token = session.access_token
    screen_name = me['name']
    provider = 'facebook'
    # finding the user(not invited) if he is already registered
    find_user = user_datastore.find_user(provider_id = provider_id)
    if find_user:
        flask.ext.security.utils.login_user(find_user)
        flash('Logged in as ' + screen_name,'info')
        return redirect(url_for('frontend.index'))
    #group creation for not invited user who is not registered
    if (find_user is None) and (grp_id is None):
        if not 'email' in me:
            flask.session['emailreq'] = True
            flask.session['provider_id'] = me['id']
            flask.session['access_token'] = session.access_token
            flask.session['screen_name'] = me['name']
        if 'email' in me:
            email = me['email']
            user = user_datastore.create_user(confirmed_at = datetime.utcnow(),\
                                              email = email,\
                                              provider = provider,\
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
    if (find_user is None) and (not grp_id is None):
        i = Invitations.query.filter(Invitations.id == inv_id).first()
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
        g = Group.query.filter(Group.id == grp_id).first()
        g.users.append(u)
        i.accepted = True
        db.session.commit()
        # person who has invited also will join to the group of the person who got invitation
        g_who_got_invitation=Group.query.filter(Group.owner_id == u.id).first()
        # user instance who has invited
        usr_who_has_invited = User.query.filter(User.id == g.owner_id).first()
        g_who_got_invitation.users.append(usr_who_has_invited)
        db.session.commit()
        #flask.session.pop('group_id', None)
        #flask.session.pop('inv_id', None)
        flask.ext.security.utils.login_user(user)
        flash('You are now registered in this program','info')
        flash('You are added to the group' + grp_id, 'info')
        flash('Logged in as ' +i.email, 'info')
        return redirect(url_for('frontend.index'))
    return redirect(url_for('frontend.index'))

@fbook.route('/get_email',methods=['GET','POST'])
def get_email():
    form = Getemail(request.form)
    if request.method == 'POST' and form.validate():
        email = request.form['email']
        if User.query.filter(User.email == email).count() > 0:
            flash('this  ' + email + '  email is associated with an account','danger')
            return redirect(url_for('frontend.index'))
        else:
            user = user_datastore.create_user(confirmed_at = datetime.utcnow(),\
                                          email = email,\
                                          provider = 'facebook',\
                                          provider_id = flask.session['provider_id'],\
                                          password = flask.ext.security.utils.encrypt_password(password_generator(8)),\
                                          provider_access_token = flask.session['access_token'] )
            db.session.add(user)
            db.session.commit()
            # group creation for normal  and unregistered user who is not invited
            u = user_datastore.get_user(email)
            g = Group(is_admin=True, group_creation_date = datetime.utcnow(), owner_id = u.id)
            u.groups.append(g)
            db.session.commit()
            flask.ext.security.utils.login_user(user)
            flash('Logged in as ' + flask.session['screen_name'],'info')
            flask.session.pop('emailreq', None)
            flask.session.pop('provider_id', None)
            flask.session.pop('access_token', None)
            flask.session.pop('screen_name', None)
            flask.session.pop('group_id', None)
            return redirect(url_for('frontend.index'))
    return redirect(url_for('frontend.index'))



