# -*- coding: utf-8 -*-

import os

from flask import *
from flask.ext.security.signals import user_confirmed, login_instructions_sent
from flask.ext.babel import Babel
from flask.ext.security import SQLAlchemyUserDatastore, Security
from flask.ext.login import current_user
import flask.ext.restless
from sqlalchemy import event
import pprint
import urllib2
from bs4 import BeautifulSoup
from .config import DefaultConfig
from .user import User, user, Link, Role, Group, user_datastore, Category, verify_auth_token
from .settings import settings
from .twitter import twits
from .google import googs
from .facebook import fbook
from .frontend import frontend
from .admin import admin
from .extensions import db, mail, cache, login_manager, security
from .utils import INSTANCE_FOLDER_PATH
from celery_model import make_celery
from datetime import datetime, timedelta


# For import *
__all__ = ['create_app']

DEFAULT_BLUEPRINTS = (
    user,
    frontend,
    settings,
    admin,
    fbook,
    twits,
    googs,
)

def create_app(config=None, app_name=None, blueprints=None):
    """Create a Flask app."""
    if app_name is None:
        app_name = DefaultConfig.PROJECT
    if blueprints is None:
        blueprints = DEFAULT_BLUEPRINTS

    app = Flask(app_name, instance_path=INSTANCE_FOLDER_PATH, instance_relative_config=True)
    configure_app(app, config)
    configure_blueprints(app, blueprints)
    configure_extensions(app)
    configure_error_handlers(app)
    configure_api_manager(app)

    return app

def configure_app(app, config=None):
    """Different ways of configurations."""

    # http://flask.pocoo.org/docs/api/#configuration
    app.config.from_object(DefaultConfig)
    # http://flask.pocoo.org/docs/config/#instance-folders
    #app.config.from_pyfile('production.cfg', silent=True)
    if config:
        app.config.from_object(config)

def configure_extensions(app):
    # flask-sqlalchemy
    db.init_app(app)

    # flask-mail
    mail.init_app(app)

    # flask-cache
    cache.init_app(app)

    # flask-babel
    babel = Babel(app)

    @babel.localeselector
    def get_locale():
        accept_languages = app.config.get('ACCEPT_LANGUAGES')
        return request.accept_languages.best_match(accept_languages)


    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)


def after_insert_listener(mapper, connection, target):
        url_id = target.id
        get_title_metadescription.delay(url_id)
event.listen(Link, 'after_insert', after_insert_listener)

def configure_api_manager(app):
    manager = flask.ext.restless.APIManager(app, flask_sqlalchemy_db=db)

    """@login_manager.token_loader
    def verify_auth_token(token):
        s = Serializer('super-secret')
        try:
            data = s.loads(token)
        except BadSignature:
            abort(401)
            #return None # invalid token
        user = user_datastore.get_user(data['id'])
        return user"""

    def preprocessor_for_person(search_params=None, **kw):
        if search_params is None:
            return
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        person_id = request.args.get("person_id", "no_person_id")

        if len(request.args) == 0:
            search_params['filters'] = []
            search_params['filters'].append(filter_person_id)

        else:
            filter_start_date = {"name": "added_time", "op": "gte", "val": start_date}
            filter_end_date = {"name": "added_time", "op": "lte", "val": end_date}
            filter_person_id = {"name": "owner_id", "op": "eq", "val": person_id}

            # Check if there are any filters there already.
            if 'filters' not in search_params:
                search_params['filters'] = []
                # *Append* your filter to the list of filters.
                search_params['filters'].append(filter_start_date)
                search_params['filters'].append(filter_end_date)
                search_params['filters'].append(filter_person_id)

    def preprocessor_for_link(search_params=None, **kw):
        if 'Authorization' not in request.headers:
            abort(401)
        if search_params is None:
            return
        auth_token = request.headers.get('Authorization')
        if verify_auth_token(auth_token) is None:
            abort(403)
        this_u = verify_auth_token(auth_token)

        if this_u:
            person_id = this_u.id
            filter_person_id = {"name": "owner_id", "op": "eq", "val": person_id}
            start_date = request.args.get("start_date")
            end_date = request.args.get("end_date")

            if len(request.args) == 0:
                search_params['filters'] = []
                search_params['filters'].append(filter_person_id)
                filter_person_id = {"name": "owner_id", "op": "eq", "val": person_id}
                if 'filters' not in search_params:
                    search_params['filters'] = []
                search_params['filters'].append(filter_person_id)
            else:
                filter_start_date = {"name": "added_time", "op": "gte", "val": start_date}
                filter_end_date = {"name": "added_time", "op": "lte", "val": end_date}
                if 'filters' not in search_params:
                    search_params['filters'] = []
                search_params['filters'].append(filter_start_date)
                search_params['filters'].append(filter_end_date)
                search_params['filters'].append(filter_person_id)

    def check_auth_token_in_header_post(data=None, **kw):
        if 'Authorization' not in request.headers:
            abort(401)
        NOW = datetime.utcnow()
        right = NOW
        left = NOW - timedelta(hours=24)
        auth_token = request.headers.get('Authorization')
        this_u = verify_auth_token(auth_token)
        if this_u:
            user_groups = []
            for i in this_u.groups:
                user_groups.append(i.id)
            for i in this_u.groups:
                print i.id
            if Link.query.filter(Link.url == data['url'],
                               Link.added_time >= left,
                               Link.added_time <= right).count() > 0:
                print "dekho toooooooooooooooo"

                all_samelink_oneday = Link.query.filter(Link.url == data['url'],
                               Link.added_time >= left,
                               Link.added_time <= right).all()
                print "dekho toooooooooooooooo"
                a =[]
                for i in all_samelink_oneday:
                    print i.id

                for i in all_samelink_oneday:
                    i_oid = i.owner_id
                    u = User.query.filter(User.id == i_oid).first()
                    for m in u.groups:
                        if not m.id in a:
                            a.append(m.id)
                        else:
                            pass
                # shared group

                c = []
                for x in user_groups:
                    if not x in a:
                        c.append(x)
                    else:
                        pass

                # jegula te gesilo
                # url
                pprint.pprint(data['url'])
                # jegulate gesilo
                pprint.pprint(a)
                # jegula te jabe
                pprint.pprint(c)
                # user er group
                pprint.pprint(user_groups)
                if not c:
                    # all groups in this_u[] are in a[], meaning, all users got the link within one day
                    abort(409)
                else:
                    data['owner_id'] = this_u.id
            else:
                data['owner_id'] = this_u.id

                """oid = l.owner_id
                pprint.pprint(oid)
                us_ex = Group.query.filter(Group.owner_id == oid).first()
                us_now = User.query.filter(User.id == this_u.id).first()
                pprint.pprint(us_ex.id)
                a = []
                for i in us_now.groups:
                    a.append(i.id)
                # ek diner moddhe post kora link er user er group jodi ekhonkar post kora
                # user er group er modhhe thake taile link post hobe na
                if us_ex.id in a:
                    abort(409)
                else:
                    data['owner_id'] = this_u.id
            else:
                data['owner_id'] = this_u.id"""

    def group_add_to_link(result=None, **kw):

        NOW = datetime.utcnow()
        right = NOW
        left = NOW - timedelta(hours=24)

        i = result['id']
        l = Link.query.filter(Link.id == i).first()
        usr = User.query.filter(User.id == result['owner_id']).first()

        user_groups = []

        for i in usr.groups:
            user_groups.append(i.id)

        if Link.query.filter(Link.url == result['url'],
                            Link.id != result['id'],
                            Link.added_time >= left,
                            Link.added_time <= right).count() > 0:

            all_samelink_oneday = Link.query.filter(Link.url == result['url'],
                           Link.id != result['id'],
                           Link.added_time >= left,
                           Link.added_time <= right).all()
            a =[]
            for i in all_samelink_oneday:
                i_oid = i.owner_id
                u = User.query.filter(User.id == i_oid).first()
                for m in u.groups:
                    if not m.id in a:
                        a.append(m.id)
                    else:
                        pass
            c = []
            for x in user_groups:
                if not x in a:
                    c.append(x)
                else:
                    pass

            # url
            pprint.pprint(result['url'])
            # jegulate gesilo
            pprint.pprint(a)
            # jegula te jabe
            pprint.pprint(c)
            # user er group
            pprint.pprint(user_groups)

            if c:
                for z in c:
                    g_to_be_added_to_link = Group.query.filter(Group.id == z).first()
                    l.groups.append(g_to_be_added_to_link)
                    db.session.commit()

        else:
            for k in user_groups:
                g_to_be_added_to_link = Group.query.filter(Group.id == k).first()
                l.groups.append(g_to_be_added_to_link)
                db.session.commit()
        
    manager.create_api(Link, methods=['GET', 'POST', 'DELETE'],
                       url_prefix='/api/person_id',
                       preprocessors={
                           'GET_MANY': [preprocessor_for_person]}
    )

    manager.create_api(Link, methods=['GET', 'POST', 'DELETE'],
                       include_columns=['url', 'id', 'owner_id'],
                       preprocessors={
                           'GET_MANY': [preprocessor_for_link],
                           'POST': [check_auth_token_in_header_post]
                                              },
                       postprocessors={
                           'POST': [group_add_to_link]
                                              }
    )
    manager.create_api(User, methods=['GET', 'POST', 'DELETE'],
                       include_columns=['id', 'first_name', 'last_name', 'email']
    )
    manager.create_api(User, methods=['GET', 'POST', 'DELETE'],
                       url_prefix='/api/v2'
    )


def configure_blueprints(app, blueprints):
    """Configure blueprints in views."""

    for blueprint in blueprints:
        app.register_blueprint(blueprint)


def configure_error_handlers(app):
    @app.errorhandler(401)
    def custom_401(error):
        return jsonify({'code':'error','msg':'Incorrect, Login Information Incorrect'}),401

    @app.errorhandler(409)
    def custom_409(error):
        return jsonify({'code':'error','msg':'Unauthorized, same link in same day/group'}),409

celery = make_celery(create_app())

@celery.task
def send_security_email(msg):
    # Use the Flask-Mail extension instance to send the incoming ``msg`` parameter
    # which is an instance of `flask_mail.Message`
    mail.send(msg)


@celery.task
def get_title_metadescription(lnkurl_id):
    lnk_obj = Link.query.filter(Link.id == lnkurl_id).first()
    try:
        lnk_url = lnk_obj.url
        soup = BeautifulSoup(urllib2.urlopen(lnk_url).read())
        web_title = soup.find('title').string
        md = ''
        l = soup.findAll("meta", attrs={"name":"description"})
        if l == []:
            md = "No meta description"
        else:
            md = l[0]['content']
        lnk_obj.title = web_title
        lnk_obj.meta_description = md
        db.session.commit()
    except AttributeError:
        print "link object of specific url can not be created"
    except IOError:
        print "connection problem, connection can not be established"
    except UnboundLocalError:
        print "local variable assignment error"

def user_confirmed_sighandler(sender, **extra):
    u_id = extra['user'].id
    u = user_datastore.get_user(u_id)
    g = Group(is_admin=True, group_creation_date = datetime.utcnow(), owner_id = u_id)
    u.groups.append(g)
    db.session.commit()
user_confirmed.connect(user_confirmed_sighandler)

def user_login(sender, **extra):

    m = {"authkey":current_user.generate_auth_token()}
    flash(m)
    return jsonify({'code':'error','msg':'Forbidden, Signature Expired'}),403

flask.ext.login.user_logged_in.connect(user_login)