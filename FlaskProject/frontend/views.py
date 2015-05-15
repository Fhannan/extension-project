# -*- coding: utf-8 -*-
from flask import *
import flask.ext.restless
from flask.ext.login import current_user
from ..user import Getemail, Invitations, user_datastore, Group, db, User
from .forms import RegisterForInvite, LoginForInvite
from datetime import datetime
from flask.ext.security import utils
import pprint

frontend = Blueprint('frontend', __name__)

@frontend.route('/')
def index():
    #current_app.logger.debug('debug')
    if 'inv' in request.args:
        inv_id = request.args.get('inv_id')
        grp_id = request.args.get('grp_id')
        e = Invitations.query.filter(Invitations.id == inv_id).first()
        if e.accepted == True:
            return 'this person is already registered and added into your group'
        if e.accepted == False:
            return redirect(url_for('frontend.register_after_invited', inv=1, inv_id=inv_id, grp_id=grp_id))
    form = Getemail(request.form)
    if current_user.has_role('Admin'):
        return redirect(url_for('admin.index'))
    elif current_user.is_authenticated() and not current_user.has_role('Admin'):
        return redirect(url_for('user.index'))
    return render_template('index.html', form=form)

# in invited user first comes to this view
@frontend.route('/register_after_invited', methods=['GET', 'POST'])
def register_after_invited():
    form = RegisterForInvite(request.form)
    grp_id = request.args.get('grp_id')
    inv_id = request.args.get('inv_id')
    e = Invitations.query.filter(Invitations.id == inv_id).first()
    email = e.email
    return render_template('frontend/registerforinvite.html', form=form,\
                           email=email,\
                           grp_id=grp_id,\
                           inv_id=inv_id)

# when an invited user clicks register then this part executes
@frontend.route('/reg_invite', methods=['GET', 'POST'])
def reg_invite():
    form = RegisterForInvite(request.form)
    grp_id = request.form['groupid']
    inv_id = request.form['invid']
    email = request.form['email']
    if request.method == 'POST' and form.validate():

        password = request.form['confirm']
        gid = request.form['groupid']
        iid = request.form['invid']
        email = request.form['email']
        find_user = user_datastore.get_user(email)
        if find_user:
             flash('You are already registered in this program,please log in','info')

        # finding the user (invited) if he is already registered
        # registration, group creation and group joining for invited user who is not registered
        if not find_user:

            user = user_datastore.create_user(confirmed_at = datetime.utcnow(),\
                                                 password = flask.ext.security.utils.encrypt_password(password),\
                                                 email = email)
            db.session.add(user)
            db.session.commit()
            u = user_datastore.get_user(email)
            #create a group for that new user
            g_add = Group(is_admin=True, group_creation_date = datetime.utcnow(), owner_id = u.id)
            u.groups.append(g_add)
            #joining to that invited group
            g = Group.query.filter(Group.id == gid).first()
            g.users.append(u)
            e = Invitations.query.filter(Invitations.id == iid).first()
            e.accepted = True
            db.session.commit()
            # person who has invited also will join to the group of the person who got invitation
            g_who_got_invitation=Group.query.filter(Group.owner_id == u.id).first()
            # user instance who has invited
            usr_who_has_invited = User.query.filter(User.id == g.owner_id).first()
            g_who_got_invitation.users.append(usr_who_has_invited)
            db.session.commit()
            #login the user with messages
            flask.ext.security.utils.login_user(user)
            flash('You are now registered in this program','info')
            flash('You are added to the group' + gid, 'info')
            flash('Logged in as ' +email, 'info')
            return redirect(url_for('frontend.index'))

    return render_template('frontend/registerforinvite.html', form=form,\
                            email=email,\
                            grp_id=grp_id,\
                            inv_id=inv_id)


# when an invited user clicks login then this part executes,this is only view
@frontend.route('/login_invite', methods=['GET', 'POST'])
def login_invite():
    form = LoginForInvite(request.form)
    grp_id = request.args.get('grp_id')
    inv_id = request.args.get('inv_id')
    e = Invitations.query.filter(Invitations.id == inv_id).first()
    email = e.email
    return render_template('frontend/loginforinvite.html', form=form,\
                           email=email,\
                           grp_id=grp_id,\
                           inv_id=inv_id)


# when an invited user clicks login after filled up the form, this part executes
@frontend.route('/log_invite', methods=['GET', 'POST'])
def log_invite():
    form = LoginForInvite(request.form)
    grp_id = request.form['groupid']
    inv_id = request.form['invid']
    email = request.form['email']
    if request.method == 'POST' and form.validate():
        password = request.form['password']
        email = request.form['email']
        usr = user_datastore.get_user(email)
        if not usr:
            flash('password is incorrect, please try later or register','info')
        if usr:
            tf = utils.verify_password(password, usr.password)
            if tf == True:
                grp_id = request.form['groupid']
                inv_id = request.form['invid']
                # group of the person who has invited
                g = Group.query.filter(Group.id == grp_id).first()
                g.users.append(usr)
                i = Invitations.query.filter(Invitations.id == inv_id).first()
                i.accepted = True
                db.session.commit()
                # find the group of the user who got invitation
                g_who_got_invitation=Group.query.filter(Group.owner_id == usr.id).first()
                # user instance who has invited
                usr_who_has_invited = User.query.filter(User.id == g.owner_id).first()
                g_who_got_invitation.users.append(usr_who_has_invited)
                db.session.commit()
                flask.ext.security.utils.login_user(usr)
                flash('you are already registerd in this program','info')
                flash('you are added to the group','info')
                flash('Logged in as ' + usr.email,'info')
                return redirect(url_for('frontend.index'))
            if tf == False:
                flash('password is incorrect, please try again later or register','info')
    return render_template('frontend/loginforinvite.html', form=form,\
                           email=email,\
                           grp_id=grp_id,\
                           inv_id=inv_id)



