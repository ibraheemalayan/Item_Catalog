#!/usr/bin/env python3
# TODO Checklist
# make a public page and logged_in page
# make the json endpoints for every page on post methods
# make a README.md (copy it from logs analysis project)
# documenate your code
# style your templates
# Follow PEP 8
# check that you meet the requirements here > https://review.udacity.com/#!/rubrics/2008/view

from flask import (Flask, render_template, request, session, request, send_file,
                   make_response, redirect,jsonify, url_for, flash)
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Item, Category, User
from sqlalchemy.orm.exc import NoResultFound
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import random, string
import flask
import datetime
import os
import json
import hashlib
import requests

app = Flask(__name__)

#Connect to Database and create database db
engine = create_engine('sqlite:///Item_Cataolg.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

#Google things
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['email', 'openid' ,'profile']
API_SERVICE_NAME = 'cloudidentity'
API_VERSION = 'v1'
app.secret_key = 'MySecret'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

#FaceBook things
FB_CLIENT_SECRETS_FILE = "fb_client_secrets.json"
FB_APP_ID = json.loads(open(FB_CLIENT_SECRETS_FILE, 'r').read())['web']['app_id']
FB_APP_SECRET = json.loads(open(FB_CLIENT_SECRETS_FILE, 'r').read())['web']['app_secret']

# Login helping methods

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

# User Helper Functions
def createUser(login_session,db):
    newUser = User(name=login_session['user_data_dict']['name'],
                   email=login_session['user_data_dict']['email'],
                   picture=login_session['user_data_dict']['picture'])
    db.add(newUser)
    db.commit()
    user = db.query(User).filter_by(email=login_session['email']).one()
    db.close()
    return user.id


def getUserDBInfo(user_id,db):
    try:
        user = db.query(User).filter_by(id=user_id).one()
        db.close()
        return user
    except NoResultFound:
        db.close()
        return None


def getUserID(email,db):
    try:
        user = db.query(User).filter_by(email=email).one()
        db.close()
        return user.id
    except:
        db.close()
        return None

# Login Back-end Views FaceBook
@app.route('/fbconnect', methods = ['POST'])
def fbconnect():

    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        revoke()

    if 'state' not in session or request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    url = 'https://graph.facebook.com/oauth/access_token'

    params = { 'grant_type': 'fb_exchange_token',
               'client_id':            FB_APP_ID,
               'client_secret':    FB_APP_SECRET,
               'fb_exchange_token': access_token}

    fb_creds = requests.get(url, params=params).json()

    if 'error' in fb_creds:
        response = make_response(json.dumps(' Error getting user credentials '), 401)
        response.headers['Content-Type'] = 'application/json'
        print('##### ERR > ' + str(fb_creds))
        return response

    user_info_url = 'https://graph.facebook.com/v5.0/me'

    params = { 'grant_type': 'fb_exchange_token',
               'access_token':      access_token,
               'fields':  'id,name,picture,email'}


    user_info = requests.get(user_info_url, params = params).json()

    if 'error' in user_info:
        response = make_response(json.dumps(' Error retreiving user info '), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # user_info Looks like:
    #{ 'id': '2471506383107297',
    #  'name': 'ibraheem alyan',
    #  'picture': {
    #     'data': {
    #          'height': 50,
    #          'is_silhouette': False,
    #          'url': 'https://platform-lookaside.fbsbx.com/platform/profilepic/?asid=2471506383107297&height=50&width=50&ext=1577365910&hash=AeT_765TqTggaZY_',
    #          'width': 50}},
    #  'email': 'ibraheemalayan@gmail.com'}

    user_info['picture'] = user_info['picture']['data']['url']

    # Now user_info Looks like:
    #{ 'id': '2471506383107297',
    #  'name': 'إبراهيم عليان',
    #  'picture': 'https://platform-lookaside.fbsbx.com/platform/profilepic/?asid=2471506383107297&height=50&width=50&ext=1577365910&hash=AeT_765TqTggaZY_',
    #  'email': 'ibraheemalayan@gmail.com'}

    session['user_data_dict'] = user_info
    session['provider'] = 'Facebook'
    session['fb_access_token'] = access_token
    session['signed'] = True

    user_db_id = getUserID(session['user_data_dict']['email'],DBSession())
    if not user_db_id:
        user_db_id = createUser(session,DBSession())
    session['user_db_id'] = user_db_id

    return redirect('/?flash=LS')

# Login Back-end Views Google

@app.route('/get_google_user_info')
def get_google_user_info():

    if 'signed' in session and session['signed'] :
        if session['provider'] == 'Google':
            return redirect('google_authorize')
        else:
            return revoke('/get_google_user_info')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **session['google_credentials'])

    result = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Save credentials back to session
    session['google_credentials'] = credentials_to_dict(credentials)

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.token, 'alt': 'json'}

    data = None
    try:
        data = requests.get(userinfo_url, params=params)
        print("DATA"+str(data))

    except:
        return redirect(url_for('get_google_user_info'))

    print("DATA"+str(data))

    if 'error' in data:
        return redirect(url_for('google_authorize'))

    json_user_data = data.json()

    # user_data_dict looks like >
    #"{'id': '114101744704852822727',
    #  'email': 'ibraheemalayan@gmail.com',
    #  'verified_email': True,
    #  'name': 'ibraheem Alayan',
    #  'given_name': 'ibraheem',
    #  'family_name': 'Alayan',
    #  'picture': 'https://lh3.googleusercontent.com/a-/AAuE7mBFRH0mLsQsnU3kqgFZ6l0_N6rHghZGYhMPdhCh5Q',
    #  'locale': 'en-GB'}"

    # removing unneeded pairs
    del json_user_data['id'] # we will replace with an id from our database based on the email
    del json_user_data['verified_email']
    del json_user_data['given_name']
    del json_user_data['family_name']
    del json_user_data['locale']

    session['user_data_dict'] = json_user_data
    session['provider'] = 'Google'
    session['signed'] = True

    user_db_id = getUserID(session['user_data_dict']['email'],DBSession())
    if not user_db_id:
        user_db_id = createUser(session,DBSession())
    session['user_data_dict']['id'] = user_db_id

    return redirect('/')

@app.route('/google_authorize')
def google_authorize():
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        session['redirect_uri_post_revoke'] = '/google_authorize'
        return redirect('/revoke')

    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = url_for('google_oauth2callback', _external=True)

    # get the url the user sign in to
    authorization_url, state = flow.authorization_url(
      access_type='offline', include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    session['state'] = state

    return redirect(authorization_url)

@app.route('/google_oauth2callback')
def google_oauth2callback():
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        session['redirect_uri_post_revoke'] = '/google_authorize'
        return redirect('/revoke')

    # Specify the state when creating the flow in the callback so that it can
    # be verified in the authorization server response.
    state = session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('google_oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    credentials = flow.credentials
    session['google_credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('get_google_user_info'))

# Login Views

@app.route("/login")
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    session['state'] = state
    response = make_response(render_template("login.html"))
    response.set_cookie('state', state)
    return response

@app.route("/internal_login", methods = ['POST'])
def internal_login():

    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        revoke()

    if 'email' not in request.form or 'password' not in request.form:
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    email = request.form.get("email")
    password = request.form.get("password")

    hasher = hashlib.sha256()
    hasher.update(password.encode())
    hashed_password = hasher.hexdigest()

    user = None

    if not getUserID(email,DBSession()):
        return '<h2> invalid email to retry click <a href="' + url_for('login') + '">here</a></h2>'

    user = getUserDBInfo(getUserID(email,DBSession()), DBSession())

    if user.password_hash != hashed_password:
         return '<h2> invalid password to retry click <a href="' + url_for('login') + '">here</a></h2>'

    session['signed'] = True
    session['provider'] = 'Internal'
    user_data_dict = {
                       'name'    : user.name ,
                       'email'   : user.email ,
                       'picture' : user.picture ,
                       'id'      : user.id }

    session['user_data_dict'] = user_data_dict

    # save a cookie to the user sth unique to indicate that he is logged in and make a revoke internal function
    return redirect( url_for('index') )

@app.route("/sign_up", methods = ['POST', 'GET'])
def internal_sign_up():
    if request.method != 'POST':
        return render_template("sign_up.html")

    if not ( request.form and  'name'            in request.form and
                           'pic_url'         in request.form and
                           'email'           in request.form and
                           'verify_email'    in request.form and
                           'password'        in request.form and
                           'verify_password' in request.form ) :
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    name            = request.form['name']
    pic_url         = request.form['pic_url']
    email           = request.form['email']
    verify_email    = request.form['verify_email']
    password        = request.form['password']
    verify_password = request.form['verify_password']

    if len(name) > 249:
        statment = 'Name too long ,<a href="/sign_up">Try again here</a>'
        return render_template('sign_up_Err.html',statment = statment)

    if len(pic_url) > 499:
        statment = 'picture URL too long <a href="'
        statment += url_for('internal_sign_up')
        statment += '" >Try again Here</a>'
        return render_template('sign_up_Err.html',statment = statment)

    if email != verify_email:
        statment = 'Confirm email doesn\'t equal the first email <a href="'
        statment += url_for('internal_sign_up')
        statment += '" >Try again Here</a>'
        return render_template('sign_up_Err.html',statment = statment)

    if len(email) > 99:
        statment = 'email too long <a href="'
        statment += url_for('internal_sign_up')
        statment += '" >Try again Here</a>'
        return render_template('sign_up_Err.html',statment = statment)

    if password != verify_password:
        statment = 'Confirm password doesn\'t equal the first password <a href="'
        statment += url_for('internal_sign_up')
        statment += '" >Try again Here</a>'
        return render_template('sign_up_Err.html',statment = statment)

    if len(password) > 65:
        statment = 'password too long <a href="'
        statment += url_for('internal_sign_up')
        statment += '" >Try again Here</a>'
        return render_template('sign_up_Err.html',statment = statment)

    if len(pic_url) < 10:
        pic_url = 'http://cdn.onlinewebfonts.com/svg/img_513928.png'

    user = None

    hasher = hashlib.sha256()
    hasher.update(password.encode())
    hashed_password = hasher.hexdigest()

    # if we fond an email with hashed password then there is an account for this email in our internal login system
    # if we found an email without a password then this user has an account with google or facebook and we will create a internal account for him with the new password
    if getUserID(email, DBSession()):
        user_db_id = getUserID(email, DBSession())
        user = getUserDBInfo(user_db_id, DBSession())
        if user.password_hash and len(user.password_hash) > 0:
            statment = 'this email already has an account and a password <a href="'
            statment += url_for('internal_sign_up')
            statment += '" >Try again Here</a> Or <a href="'
            statment += url_for('login')
            statment += '" >Log in Here</a>'
            return render_template('sign_up_Err.html',statment = statment)

        # here the user have an account but not with the internal login system (google or facebook)
        # so if he is signed in we will save the password in the database with the user with the email
        # but if not then we will send an error messeage showing that this email is associated with a user account but not in our log in system
        # so if he is that user we will redirect him to the login form to sign with google or facebook and to fill the sign up form another time while he is signed

        if 'signed' in session and session['signed'] and session['user_data_dict']['email'] == email:

            user.password_hash = hashed_password

            db = DBSession()

            db.add(user)
            db.commit()
            db.close()

            return redirect( url_for('login') )

        statment = ('this email already has an account in this website <br>' +
        ' but not in our internal login system (facebook or google) <br>' +
        'if you want to create an account in our local system ' +
        'please log in to your foreign account and try again <br>' +
        '<a href="')
        statment += url_for('internal_sign_up')
        statment += '" >Try again Here</a> Or <a href="'
        statment += url_for('login')
        statment += '" >Log in Here</a>'
        return render_template('sign_up_Err.html',statment = statment)


    user = User(name = name, email = email, password_hash = hashed_password, picture = pic_url)

    db = DBSession()

    db.add(user)
    db.commit()
    db.close()

    return redirect( url_for('login') )

# Revoking functions

def revoke_fb(session, redirect_path):

    access_token = session['fb_access_token']
    url = 'https://graph.facebook.com/%s/permissions' % session['user_data_dict']['id']
    params = { 'access_token' : access_token }
    result = requests.delete(url, params = params)

    del session['fb_access_token']
    if 'user_data_dict' in session:
        del session['user_data_dict']

    session['provider'] = 'None'
    session['signed'] = False

    return redirect(redirect_path)

def revoke_google(session, redirect_path):
    if 'google_credentials' not in session:
      return redirect( redirect_path )

    credentials = google.oauth2.credentials.Credentials(
      **flask.session['google_credentials'])

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
        params={'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:

        del session['google_credentials']
        if 'user_data_dict' in session:
            del session['user_data_dict']
        session['signed'] = False
        session['provider'] = 'None'

        return redirect( redirect_path )
    else:
        del session['google_credentials']
        if 'user_data_dict' in session:
            del session['user_data_dict']
        session['signed'] = False
        session['provider'] = 'None'

        print('An error occurred while revoking credentials : ' + str(revoke.json()))

        return redirect( redirect_path )

def revoke_internal(redirect_path):

    if 'user_data_dict' in session:
        del session['user_data_dict']
    session['signed'] = False
    session['provider'] = 'None'

    return redirect( redirect_path )


@app.route('/revoke')
def revoke():

    if not 'redirect_uri_post_revoke' in session:
        redirect_path = '/?flash=SO'
    else:
        redirect_path = session['redirect_uri_post_revoke']
        del session['redirect_uri_post_revoke']

    if 'signed' not in session:
        session['signed'] = False
    if 'provider' not in session:
        session['provider'] = 'None'
    if session['signed']:
        if session['provider'] == 'Google':
            return revoke_google(session, redirect_path)
        elif session['provider'] == 'Facebook':
            return revoke_fb(session, redirect_path)
        else:
            return revoke_internal(redirect_path)
    else:
        session['signed'] = False
        session['provider'] = 'None'
        if 'user_data_dict' in session:
            del session['user_data_dict']

        return redirect( redirect_path )


# Static files routers

@app.route('/css/<string:path>')
def get_css(path):
    return send_file( ('templates\\css\\' + str(path).replace('/', '\\')), cache_timeout=-1 )

@app.route('/js/<string:path>')
def get_js(path):
    return send_file( ('templates\\js\\' + str(path).replace('/', '\\')), cache_timeout=-1 )

@app.route('/img/<string:path>')
def get_img(path):
    return send_file( ('templates\\img\\' + str(path).replace('/', '\\')), cache_timeout=-1 )
#
# @app.route('/webfonts/<string:path>')
# def get_webfonts(path):
#     return send_file( ('templates\\webfonts\\' + str(path).replace('/', '\\')), cache_timeout=-1 )
#
# @app.route('/fonts/<string:path>')
# def get_fonts(path):
#     return send_file( ('templates\\fonts\\' + str(path).replace('/', '\\')), cache_timeout=-1 )
#

# Views

@app.route('/')
def index():
    db = DBSession()
    categories = db.query(Category).all()
    latest_items = db.query(Item).order_by(desc(Item.id)).limit(5)

    db.close()

    if 'signed' not in session:
        session['signed'] = False

    if session['signed']:
        return render_template("logged_in_index.html" ,
                               categories = categories,
                               items = latest_items,
                               user_dict = session["user_data_dict"])

    return render_template("public_index.html" , categories = categories, items = latest_items)


@app.route('/catalog/<string:cat_name>/items')
def view_category_items(cat_name):
    db = DBSession()
    category = None
    items = None
    try:
        category = db.query(Category).filter_by(name = cat_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/category_404.html", cat_name = cat_name)

    try:
        items = db.query(Item).filter_by(cat_id = category.id)
    except NoResultFound:
        db.close()
        return render_template("errors/category_empty.html", cat_name = cat_name)

    db.close()

    return render_template("public_category.html" , cat = category, items = items)


@app.route('/catalog/<string:cat_name>/<string:item_name>')
def view_item(cat_name, item_name):
    db = DBSession()
    category = None
    item = None
    try:
        category = db.query(Category).filter_by(name = cat_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/category_404.html", cat_name = cat_name)

    try:
        item = db.query(Item).filter_by(cat_id = category.id, title = item_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/item_404.html", cat_name = cat_name, item_name = item_name)

    author = db.query(User).filter_by(id = item.author_id).one()
    db.close()

    return render_template("public_item.html" , cat = category, item = item, author = author)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    # facebook login works only over https
    app.run(host = '0.0.0.0', port = 5000, ssl_context='adhoc')
