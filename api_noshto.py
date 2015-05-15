#important links for celery
#http://docs.celeryproject.org/en/master/getting-started/first-steps-with-celery.html
#http://flask.pocoo.org/docs/patterns/celery/
#https://pythonhosted.org/Flask-Security/customizing.html
#http://www.nkrode.com/article/real-time-dashboard-for-redis
# $ sudo pip install celery
# $ sudo pip install redis-server
from flask import Flask, redirect, url_for, session, Response, request
from flask import request, g
from flask import *
from flask.ext.sqlalchemy import SQLAlchemy
import flask.ext.restless
import urllib2
import pprint
from bs4 import BeautifulSoup
from time import gmtime, strftime
import datetime
import simplejson as json
from datetime import datetime, timedelta
from flask_mail import Mail
from flask_mail import Message
import os
import sys
import pprint
from flask.ext.security import Security, SQLAlchemyUserDatastore,\
    UserMixin, RoleMixin, login_required, current_user
from forms import UpdateProfileForm
from celery import Celery
from sqlalchemy import event
import dbmodel
from dbmodel import User, Link, db, Role
import settings
#from flask.ext.login import login_user, logout_user, current_user, login_required, LoginManager
#from werkzeug.security import generate_password_hash, \
#     check_password_hash
# Create the Flask application and the Flask-SQLAlchemy object.
app = Flask(__name__)
app.config.from_object(settings)

mail = Mail(app)
db = flask.ext.sqlalchemy.SQLAlchemy(app)
# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

#create the database tables
db.create_all()

def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    TaskBase = celery.Task
    class ContextTask(TaskBase):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
    return celery

celery = make_celery(app)

@celery.task
def send_security_email(msg):
    # Use the Flask-Mail extension instance to send the incoming ``msg`` parameter
    # which is an instance of `flask_mail.Message`
    mail.send(msg)

@celery.task
def get_title_metadescription(url_id):
    lnk_obj = Link.query.get(url_id)
    lnk_obj.title = url_extractor(lnk_obj.url)['title']
    lnk_obj.meta_description = url_extractor(lnk_obj.url)['meta_description']
    db.session.commit()
    # Use the Flask-Mail extension instance to send the incoming ``msg`` parameter
    # which is an instance of `flask_mail.Message`

"""roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column('password', db.String(256))
    email = db.Column('email', db.String(50), unique=True, index=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(255))
    current_login_ip = db.Column(db.String(255))
    login_count = db.Column(db.Integer)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    def __str__(self):
        return '<User id=%s email=%s>' % (self.id, self.email)

class Link(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Unicode)
    added_time = db.Column(db.DateTime, default=datetime.utcnow())
    title = db.Column(db.String(255))
    meta_description = db.Column(db.String(1024))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = db.relationship('User', backref=db.backref('links',
                                                         lazy='dynamic'))"""

def url_extractor(url):
    soup = BeautifulSoup(urllib2.urlopen(url).read())
    web_title = soup.find('title').string
    md = soup.findAll("meta", attrs={"name": "description"})[0]['content'].encode('utf-8')
    return dict(title=web_title, meta_description=md)


def after_insert_listener(mapper, connection, target):
    # 'target' is the inserted object
    #new_url = target.url
    url_id = target.id
    #lnk_obj = Link.query.get(url_id)
    #pprint.pprint(lnk_obj)
    #pprint.pprint(lnk_obj.id)
    #pprint.pprint(lnk_obj.url)
    #pprint.pprint(lnk_obj.title)
    get_title_metadescription.delay(url_id)

event.listen(Link, 'after_insert', after_insert_listener)

@security.send_mail_task
def delay_security_email(msg):
    send_security_email.delay(msg)

@app.route('/')
def home():
    #pprint.pprint(current_user.get_auth_token())
    return render_template("hello.html")

@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    user = User.query.get(current_user.id)
    pprint.pprint(user.first_name)
    form = UpdateProfileForm(request.form, obj=user)
    if request.method == 'POST' and form.validate() and current_user.is_authenticated():
        form.populate_obj(user)
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        db.session.commit()
        flash('your data has been updated')
        return redirect(url_for('home'))
    return render_template('profile_update.html', form=form)
# Create your Flask-SQLALchemy models as usual but with the following two
# (reasonable) restrictions:
#   1. They must have a primary key column of type sqlalchemy.Integer or
#      type sqlalchemy.Unicode.
#   2. They must have an __init__ method which accepts keyword arguments for
#      all columns (the constructor in flask.ext.sqlalchemy.SQLAlchemy.Model
#      supplies such a method, so you don't need to declare a new one).
# This line was added by Mahbub
#class Person(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    name = db.Column(db.Unicode, unique=True)
#datetime.datetime.utcnow()
# Create the Flask-Restless API manager.

manager = flask.ext.restless.APIManager(app, flask_sqlalchemy_db=db)

def preprocessor_for_person(search_params=None, **kw):
    if search_params is None:
        return
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    person_id = request.args.get("person_id", "no_person_id")

    if len(request.args) == 0:
        search_params['filters'] = []

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
    if search_params is None:
        return

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    if len(request.args) == 0:
        search_params['filters'] = []
    else:
        filter_start_date = {"name": "added_time", "op": "gte", "val": start_date}
        filter_end_date = {"name": "added_time", "op": "lte", "val": end_date}
        if 'filters' not in search_params:
            search_params['filters'] = []
        search_params['filters'].append(filter_start_date)
        search_params['filters'].append(filter_end_date)

def samelink_sameday_error(data=None, **kw):
    NOW = datetime.utcnow()
    right = NOW
    left = NOW - timedelta(hours=24)

    if Link.query.filter(Link.url == data['url'],
                         Link.added_time >= left,
                         Link.added_time <= right).count() > 0:
        raise flask.ext.restless.ProcessingException(description='Not Authorized',
                                                     code=409)

# Create API endpoints, which will be available at /api/<tablename> by
# default. Allowed HTTP methods can be specified as well.

manager.create_api(Link, methods=['GET', 'POST', 'DELETE'],
                   url_prefix='/api/person_id',
                   preprocessors={
                       'GET_MANY': [preprocessor_for_person]}
)
manager.create_api(Link, methods=['GET', 'POST', 'DELETE'],
                   preprocessors={
                       'GET_MANY': [preprocessor_for_link],
                       'POST': [samelink_sameday_error]
                   }
)
manager.create_api(User, methods=['GET', 'POST', 'DELETE'])

# start the flask loop




