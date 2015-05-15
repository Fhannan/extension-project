from flask import *
import flask
import flask.ext.sqlalchemy
import flask.ext.restless
import urllib2
from bs4 import BeautifulSoup
from time import gmtime, strftime
import datetime


# Create the Flask application and the Flask-SQLAlchemy object.
app = flask.Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = flask.ext.sqlalchemy.SQLAlchemy(app)

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

class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode, unique=True)
    linksets = db.relationship('Link')

class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Unicode, unique=True)
    added_time = db.Column(db.DateTime)
    owner_id = db.Column(db.Integer, db.ForeignKey('person.id'))


#class Link(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    url = db.Column(db.Unicode, unique=True)
#    added_time = db.Column(db.DateTime)
#    owner_id = db.Column(db.Integer, db.ForeignKey('person.id'))
#    owner = db.relationship('Person', backref=db.backref('links',
#                                                         lazy='dynamic'))

# Create the database tables.
db.create_all()

# Create the Flask-Restless API manager.
manager = flask.ext.restless.APIManager(app, flask_sqlalchemy_db=db)


def preprocessor(search_params=None, **kw):
    # This checks if the preprocessor function is being called before a
    # request that does not have search parameters.
    if search_params is None:
        return
    # Create the filter you wish to add; in this case, we include only
    # instances with ``id`` not equal to 1.
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    filt_1 = {"name" :"added_time", "op" :"gte", "val" :start_date}
    filt_2 = {"name" :"added_time", "op" :"lte", "val" :end_date}

    # Check if there are any filters there already.
    if 'filters' not in search_params:
        search_params['filters'] = []
    # *Append* your filter to the list of filters.
    search_params['filters'].append(filt_1)
    search_params['filters'].append(filt_2)



def get_single_preprocessor(search_params=None, **kw):
    # This checks if the preprocessor function is being called before a
    # request that does not have search parameters.
    if search_params is None:
        return
    # Create the filter you wish to add;

    #start_date = request.args.get("start_date")
    #end_date = request.args.get("end_date")
    req_id = request.args.get("req_id")
    added_time = request.args.get("added_time")
    filt = {"name" :"id", "op" :"eq", "val" :req_id}
    filt2 = {"name" :"linksets[].added_time", "op" :"gte", "val" :added_time}
    #filt_1 = {"name" :"added_time", "op" :"gte", "val" :start_date}
    #filt_2 = {"name" :"added_time", "op" :"lte", "val" :end_date}

    # Check if there are any filters there already.
    if 'filters' not in search_params:
        search_params['filters'] = []
    # *Append* your filter to the list of filters.
    search_params['filters'].append(filt)
    search_params['filters'].append(filt2)

# Create API endpoints, which will be available at /api/<tablename> by
# default. Allowed HTTP methods can be specified as well.
manager.create_api(Person, methods=['GET', 'POST', 'DELETE'],
                   preprocessors=dict(GET_MANY=[get_single_preprocessor]))
manager.create_api(Link, methods=['GET', 'POST', 'DELETE'],
                   preprocessors=dict(GET_MANY=[preprocessor]))

# start the flask loop
app.run()
