# -*- coding: utf-8 -*-

import os

from flask import *
import flask.ext.restless
from flask import current_app as APP
from flask.ext.login import login_required, current_user
from .models import User, Link, Group, user_datastore, Category, db, verify_auth_token
from .forms import UpdateProfileForm
import pprint
from datetime import datetime
from sqlalchemy import Date, cast, or_



user = Blueprint('user', __name__, url_prefix='/user')


# it give the auth key of current user
@user.route('/authkey')
def authkey():
    return current_user.generate_auth_token()

@user.route('/api/login', methods = ['POST'])
def create_person():
    auth_token = None    
    if not request.json and 'password' not in request.json:
        abort(401)
    this_email = request.json.get('email')
    this_password = request.json.get('password')
    if User.query.filter(User.email == this_email).count() == 0:
        abort(401)
        raise flask.ext.restless.ProcessingException(description='Not Authorized',
                                                     code=401)
    elif User.query.filter(User.email == this_email).count() == 1:
        u = User.query.filter(User.email == this_email)
        pwhash = u[0].password
        if u and flask.ext.security.utils.verify_password(this_password, pwhash):
            auth_token = u[0].get_auth_token()
        else:
            abort(401)

    identity = {
        'email': this_email,
        'password':this_password,
        'authentication_token':auth_token
        }
    return jsonify({'identity': identity})

@user.route('/api/category', methods=['POST', 'DELETE'])
def create_link_category_relationship():
    if not request.json:
        abort(401)
    response = None
    if 'Authorization' not in request.headers:
            abort(401)
    auth_token = request.headers.get('Authorization')
    this_u = verify_auth_token(auth_token)
    if this_u:
        if request.method == 'DELETE':
            lid = request.json.get('id')
            i = Category.query.filter(Category.id == lid).first()
            db.session.delete(i)
            db.session.commit()
            response = {
                'id': lid
                    }
            return jsonify({'response': response})
        if request.method == 'POST':
            lid = request.json.get('link_id')
            cat = request.json.get('category')
            if Category.query.filter(Category.category == cat).count() == 0:
                c = Category(category = cat)
                db.session.add(c)
                db.session.commit()
                c = Category.query.filter(Category.category == cat).first()
                l = Link.query.filter(Link.id == lid).first()
                c.links.append(l)
                db.session.commit()

                response = {
                    'category': cat,
                    'link_id': lid
                             }
            else:
                c = Category.query.filter(Category.category == cat).first()
                l = Link.query.filter(Link.id == lid).first()
                c.links.append(l)
                db.session.commit()
                response = {
                    'category': cat,
                    'link_id': lid
                        }
            return jsonify({'response': response})


@user.route('/')
@login_required
def index():
    if not current_user.is_authenticated():
        abort(403)
    email = current_user.email
    u = user_datastore.get_user(email)
    p=[]
    for m in u.groups:
        p.append(m.id)

    today = datetime.utcnow().strftime('%Y-%m-%d')

    return render_template('user/index.html',today = today, email=email, p=p)



@user.route('/show_links')
@login_required
def show_links():
    usr = user_datastore.get_user(current_user.id)
    usr_grps = usr.groups
    g = []
    for i in usr_grps:
        g.append(i.id)
    pprint.pprint(g)
    dict_col = {'0':'url',
                '1':'added_time',
                '2':'title',
                '3':'meta_description',
                '4':'owner_id'}
    start_date = request.args.get('datebox[start_date]')
    end_date = request.args.get('datebox[end_date]')
    s_val = request.args.get('search[value]')
    col_no = request.args.get('order[0][column]')
    order_dir = request.args.get('order[0][dir]')
    pageStart = request.args.get('start')
    pageLen = request.args.get('length')

    if (start_date =="" or start_date is None) and (end_date =="" or end_date is None):
        qry = Link.query.\
                     filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")),Link.owner_id.in_((g))).\
                     order_by(dict_col[col_no]+" "+order_dir).\
                     offset(pageStart).\
                     limit(pageLen).\
                     all()
        qry_count = Link.query.filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), Link.owner_id.in_((g))).count()

    """if not (start_date is None) and not (end_date is None) and start_date==end_date:
        #temp = datetime.strptime(start_date, '%Y-%m-%d').date()
        #end_date = temp + timedelta(days=1)
        #pprint.pprint(temp)
        qry = Link.query.\
                     filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), cast(Link.added_time,Date) == date.today()).\
                     order_by(dict_col[col_no]+" "+order_dir).\
                     offset(pageStart).\
                     limit(pageLen).\
                     all()

        qry_count = Link.query.filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), cast(Link.added_time,Date) == date.today()).count()"""

    if start_date != end_date:
        qry = Link.query.\
                        filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), Link.added_time >= start_date, Link.added_time <= end_date, Link.owner_id.in_((g))).\
                        order_by(dict_col[col_no]+" "+order_dir).\
                        offset(pageStart).\
                        limit(pageLen).\
                        all()

        qry_count = Link.query.filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), Link.added_time >= start_date, Link.added_time <= end_date, Link.owner_id.in_((g))).count()



    return json.dumps({'recordsTotal':Link.query.count(),'recordsFiltered':qry_count,'data':list(qry)})



@user.route('/users_in_group')
@login_required
def users_in_my_group():
    u = user_datastore.get_user(current_user.id)
    g = Group.query.filter(Group.owner_id == u.id).first()
    groups = g.users
    return render_template('user/users_in_my_group.html', groups = groups)

