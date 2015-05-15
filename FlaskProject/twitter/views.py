# -*- coding: utf-8 -*-

import os

from flask import *
import flask.ext.restless
from ..user import User, db, Getemail, user_datastore, Group, Invitations
from ..utils import password_generator
from rauth.utils import parse_utf8_qsl
from rauth.service import OAuth1Service
from datetime import datetime

twits = Blueprint('twits', __name__, url_prefix='/twits')

twitter = OAuth1Service(
    name='twitter',
    consumer_key='UMnMMvNghC2zihz8DC0as6ZCH',
    consumer_secret='qxXqz8wT0chSA4DDfaPIgw9R6TMqTmUQMX53OC7GYOHzd0dUsS',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    base_url='https://api.twitter.com/1.1/')


@twits.route('/login')
def login():
    flask.session.pop('group_id', None)
    flask.session.pop('inv_id', None)
    if not 'grp_id' in request.args:
        oauth_callback = url_for('twits.authorized', _external=True)
    if 'grp_id' in request.args:
        grp_id = request.args.get('grp_id')
        inv_id = request.args.get('inv_id')
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
        else:
            oauth_callback = 'http://staging.ivivelabs.com:3104/twits/authorized?grp_id={0}&inv_id={1}'.format(grp_id,inv_id)
    params = {'oauth_callback': oauth_callback,
              'scope':'user:email'}

    r = twitter.get_raw_request_token(params=params)
    data = parse_utf8_qsl(r.content)

    session['twitter_oauth'] = (data['oauth_token'],
                                data['oauth_token_secret'])
    return redirect(twitter.get_authorize_url(data['oauth_token'], **params))


@twits.route('/authorized')
def authorized():
    request_token, request_token_secret = session.pop('twitter_oauth')

    # check to make sure the user authorized the request
    if not 'oauth_token' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('frontend.index'))
    try:
        creds = {'request_token': request_token,
                'request_token_secret': request_token_secret}
        params = {'oauth_verifier': request.args['oauth_verifier']}
        sess = twitter.get_auth_session(params=params, **creds)
    except Exception, e:
        flash('There was a problem logging into Twitter: ' + str(e))
        return redirect(url_for('frontend.index'))

    if 'oauth_token' and 'grp_id' in request.args:
        grp_id = request.args.get('grp_id')
        inv_id = request.args.get('inv_id')
        flask.session['group_id'] = grp_id
        flask.session['invitation_id'] = inv_id

    verify = sess.get('account/verify_credentials.json',
                    params={'format':'json'}).json()

    provider = 'twitter'
    provider_id = verify['id']
    provider_access_token = sess.access_token
    screen_name = verify['name']
    find_user = user_datastore.find_user(provider_id = verify['id'])
    if find_user:
        flask.ext.security.utils.login_user(find_user)
        flash('Logged in as ' + screen_name,'info')
        return redirect(url_for('frontend.index'))
    if (find_user is None) and (not 'group_id' in flask.session):
        if not 'email' in verify:
            flask.session['twit_emailreq'] = True
            flask.session['twit_provider_id'] = verify['id']
            flask.session['twit_access_token'] = sess.access_token
            flask.session['twit_screen_name'] = verify['name']

        if 'email' in verify:
            email = verify['email']
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
        flask.session.pop('group_id', None)
        flask.session.pop('inv_id', None)
        flask.ext.security.utils.login_user(user)
        flash('You are now registered in this program','info')
        flash('You are added to the group' + grp_id, 'info')
        flash('Logged in as ' +i.email, 'info')
        return redirect(url_for('frontend.index'))
    return redirect(url_for('frontend.index'))

@twits.route('/get_email',methods=['GET','POST'])
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
                                          provider = 'twitter',\
                                          provider_id = flask.session['twit_provider_id'],\
                                          password = flask.ext.security.utils.encrypt_password(password_generator(8)),\
                                          provider_access_token = flask.session['twit_access_token'] )
            db.session.add(user)
            db.session.commit()
            # group creation for normal  and unregistered user who is not invited
            u = user_datastore.get_user(email)
            g = Group(is_admin=True, group_creation_date = datetime.utcnow(), owner_id = u.id)
            u.groups.append(g)
            db.session.commit()
            flask.ext.security.utils.login_user(user)
            flash('Logged in as ' + flask.session['twit_screen_name'],'info')
            flask.session.pop('twit_emailreq', None)
            flask.session.pop('twit_provider_id', None)
            flask.session.pop('twit_access_token', None)
            flask.session.pop('twit_screen_name', None)
            return redirect(url_for('frontend.index'))
    return redirect(url_for('frontend.index'))

