#!/usr/bin/env python3

from flask import (Flask, render_template, request, session, request,
                   send_file, make_response, redirect, jsonify, url_for, flash)
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Item, Category, User
from sqlalchemy.orm.exc import NoResultFound
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import random
import string
import flask
import datetime
import os
import sys
import json
import hashlib
import requests

sys.stdout = open('/home/ubuntu/output.log','a')

# Files Main Directory
MD = '/var/www/Item_Catalog/'

app = Flask(__name__, template_folder=(MD + '/templates'))

# Connect to Database
def get_env_variable(name):
    try:
        return os.environ[name]
    except KeyError:
        message = "Expected environment variable '{}' not set.".format(name)
        raise Exception(message)

# the values of those depend on your setup
POSTGRES_URL = '127.0.0.1:5432'
POSTGRES_USER = 'postgres'
POSTGRES_PW = 'Grader@098'
POSTGRES_DB = 'item_catalog'

# Connect to Database and create database sessionmaker (DBSession)
engine = create_engine('postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB))
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

# Google things
CLIENT_SECRETS_FILE = MD + "client_secret.json"
SCOPES = ['email', 'openid', 'profile']
API_SERVICE_NAME = 'cloudidentity'
API_VERSION = 'v1'
app.secret_key = 'MySecret'
# TODO why are those
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

# FaceBook things
FB_CLIENT_SECRETS_FILE = MD + "fb_client_secrets.json"
FB_APP_ID = json.loads(
              open(FB_CLIENT_SECRETS_FILE, 'r').read())['web']['app_id']
FB_APP_SECRET = json.loads(
                 open(FB_CLIENT_SECRETS_FILE, 'r').read())['web']['app_secret']

# Login helping methods

# #############################################################################
# ##################### Start of Login helping methods ########################
# #############################################################################


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

# ----- User Helper methods --------


# new user
def createUser(session, db, close_db=True):
    newUser = UU(name=session['user_data_dict']['name'],
                 email=session['user_data_dict']['email'],
                 picture=session['user_data_dict']['picture'])
    db.add(newUser)
    db.commit()
    user = db.query(User).filter_by(
                                email=session['user_data_dict']['email']).one()
    if close_db:
        db.close()
    return user.id


# retreive user object by id
def getUserDBInfo(user_id, db, close_db=True):

    try:
        user = db.query(User).filter_by(id=user_id).one()
        if close_db:
            db.close()
        return user
    except NoResultFound:
        if close_db:
            db.close()
        return None


# get user id by email, returns None if no result found
def getUserID(email, db, close_db=True):
    try:
        user = db.query(User).filter_by(email=email).one()
        if close_db:
            db.close()
        return user.id
    except NoResultFound:
        if close_db:
            db.close()
        return None

# #############################################################################
# ###################### End of Login helping methods #########################
# #############################################################################


# #############################################################################
# ############################# Strat of VIEWS ################################
# #############################################################################


# ____________________________________________________________________________#
# ############# Start of login and login-related views ########################
# ____________________________________________________________________________#

# ________________________ Start Facebook login views ________________________#

# receives the access token from the javascript facebook login function
@app.route('/fbconnect', methods=['POST'])
def fbconnect():

    # check if user is signed in and revoke if yes
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        revoke()

    # check the state given from the main login view
    if 'state' not in session or request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # get the access token from the post request body
    access_token = request.data

    # exchange token for credentials
    url = 'https://graph.facebook.com/oauth/access_token'

    params = {'grant_type': 'fb_exchange_token',
              'client_id':            FB_APP_ID,
              'client_secret':    FB_APP_SECRET,
              'fb_exchange_token': access_token}

    fb_creds = requests.get(url, params=params).json()

    # validate credentials
    if 'error' in fb_creds:
        messeage = 'Error getting user credentials'
        response = make_response(json.dumps(message), 401)
        response.headers['Content-Type'] = 'application/json'
        print('##### ERR > ' + str(fb_creds))
        return response

    # get user's information
    user_info_url = 'https://graph.facebook.com/v5.0/me'

    params = {'grant_type': 'fb_exchange_token',
              'access_token':      access_token,
              'fields':  'id, name, picture, email'}

    user_info = requests.get(user_info_url, params=params).json()

    # validate that user's information is received
    if 'error' in user_info:
        response = make_response(json.dumps('Error retreiving user info'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # user_info dictionary Looks like:

    # {'id': '$$$$$$$$$$$$$$',
    #  'name': 'ibraheem alyan',
    #  'picture': {
    #     'data': {
    #          'height': $$,
    #          'is_silhouette': False,
    #          'url': 'some_picture_url',
    #          'width': $$}},
    #  'email': 'ibraheemalayan@gmail.com'}

    # reshape the user_info dictionary
    user_info['picture'] = user_info['picture']['data']['url']

    # Now user_info dictionary Looks like:
    # {'id': '$$$$$$$$$$$$$$',
    #  'name': 'Ibraheem Alyan',
    #  'picture': 'some_picture_url',
    #  'email': 'ibraheemalayan@gmail.com'}

    # after success of the above operations,
    # we save the user info in the session and check that the user is logged
    session['user_data_dict'] = user_info
    session['provider'] = 'Facebook'
    session['fb_access_token'] = access_token
    session['signed'] = True

    # check if the user is new, if yes we create a new user in our database
    # store the user's database id in the session (new and old users)
    user_db_id = getUserID(session['user_data_dict']['email'], DBSession())
    if not user_db_id:
        user_db_id = createUser(session, DBSession())
    session['user_db_id'] = user_db_id

    # redirect to homepage
    return redirect(url_for('index', _external=True))

# _________________________ End Facebook login views _________________________#
# _________________________ Start Google login views _________________________#


# this view is called as the last step in our sign in with google system
# retreives user's information from google
@app.route('/get_google_user_info')
def get_google_user_info():

    # check if user is signed in and revoke if yes
    if 'signed' in session and session['signed']:
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

    # get user's information
    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.token, 'alt': 'json'}

    data = requests.get(user_info_url, params=params)

    # validate that user's information is received
    if 'error' in data:
        return redirect(url_for('google_authorize', _external=True))

    json_user_data = data.json()

    # user_data_dict dictionary looks like >
    # {'id': '114101744704852822727',
    #  'email': 'ibraheemalayan@gmail.com',
    #  'verified_email': True,
    #  'name': 'ibraheem Alayan',
    #  'given_name': 'ibraheem',
    #  'family_name': 'Alayan',
    #  'picture': 'https://lh3.googleusercontent.com/a......etc',
    #  'locale': 'en-GB'}"

    # removing unneeded pairs and reshaping the dictionary
    del json_user_data['id']    # we will replace this with an id
    #  from our database based on the email
    del json_user_data['verified_email']
    del json_user_data['given_name']
    del json_user_data['family_name']
    del json_user_data['locale']

    # after success of the above operations,
    # we save the user info in the session and check that the user is logged
    session['user_data_dict'] = json_user_data
    session['provider'] = 'Google'
    session['signed'] = True

    # check if the user is new, if yes we create a new user in our database
    # store the user's database id in the session (new and old users)
    user_db_id = getUserID(session['user_data_dict']['email'], DBSession())
    if not user_db_id:
        user_db_id = createUser(session, DBSession())
    session['user_data_dict']['id'] = user_db_id

    # redirect to homepage
    return redirect(url_for('index', _external=True))


# first google sign in view
@app.route('/google_authorize')
def google_authorize():

    # check if user is signed in and revoke if yes
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        session['redirect_uri_post_revoke'] = '/google_authorize'
        return redirect('/revoke')

    # Create flow instance to manage the
    #  OAuth2.0 Authorization Grant Flow steps
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = url_for('google_oauth2callback', _external=True)

    # get the url the user sign in to
    authorization_url, state = flow.authorization_url(
      access_type='offline', include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    session['state'] = state

    return redirect(authorization_url)


# this view is called by google's servers with the access token
@app.route('/google_oauth2callback')
def google_oauth2callback():

    # check if user is signed in and revoke if yes
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

    # get user's information
    return redirect(url_for('get_google_user_info', _external=True))


# __________________________ End Google login views __________________________#
# __________________________ Start Main login view ___________________________#

# this view returns the main login page with an anti-forgery state
@app.route("/login")
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    session['state'] = state
    response = make_response(render_template("login.html"))
    response.set_cookie('state', state)
    return response

# ___________________________ End Main login view ____________________________#
# ______________________ Start Password recovery views _______________________#


# returns the 'enter email' form template
@app.route("/password-recovery")
def password_recovery():
    return render_template('password_rec_email.html')


# handle the email input from the previouse view template
# and returns the question template for that user
@app.route("/password-recovery-security-question", methods=['POST'])
def validate_recovery_email():

    # check the post request body data form
    if 'email' not in request.form:
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    email = request.form['email']

    db = DBSession()

    # validate the email
    if not getUserID(email, db, False):
        statment = ('invalid email, <a href="/login"' +
                    ' style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    # retreive the user from the database
    user = getUserDBInfo(getUserID(email, db, False), db, False)

    db.close()

    # return the security question template
    return render_template('password_rec.html',
                           email=user.email,
                           sec_q=user.sec_q)


# handles the security question's answer given by the user
# decides if we update the password or don't
@app.route("/pr/<string:email>", methods=['POST'])
def update_password(email):

    # check if user is signed in and revoke if yes
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        revoke()

    # check the post request body data form
    if (
            not email or 'sec_a' not in request
            .form or 'n_password' not in request.form):
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    sec_a = request.form['sec_a']
    new_password = request.form['n_password']

    # check the new password validity
    if len(new_password) < 1:
        statment = ('Please enter a password, ' +
                    '<a href="/login" style="font-size:39px">Try again</a>')
        return render_template('status_message.html', statment=statment)

    if len(new_password) > 65:
        statment = ('Password is too long, ' +
                    '<a href="/login" style="font-size:39px">Try again</a>')
        return render_template('status_message.html', statment=statment)

    if len(new_password) < 8:
        statment = ('Password is too short, ' +
                    '<a href="/login" style="font-size:39px">Try again</a>')
        return render_template('status_message.html', statment=statment)
    db = DBSession()

    # retreive the user from the database
    if not getUserID(email, db, False):
        statment = ('invalid email, ' +
                    '<a href="/login" style="font-size:39px">Try again</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    user = getUserDBInfo(getUserID(email, db, False), db, False)

    # check the answer
    if user.sec_a == sec_a:

        # hash the new password if answer is correct
        hasher = hashlib.sha256()
        hasher.update(new_password.encode())

        # update the password
        user.password_hash = hasher.hexdigest()

        db.add(user)
        db.commit()

        db.close()

        # return status template shows the success
        statment = ('Password was updated successfully, <a href="/login" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    # if answer is incorrect return status template shows the result
    db.close()
    statment = ('Security answer is incorrect, ' +
                '<a href="/login" style="font-size:39px">Try again here</a>')
    return render_template('status_message.html', statment=statment)

# ______________________ Start Password recovery views _______________________#
# ________________________ Start internal login view _________________________#


# receives post request from the main login page
@app.route("/internal_login", methods=['POST'])
def internal_login():

    # check if user is signed in and revoke if yes
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        revoke()
    # checks the post request body data form
    if 'email' not in request.form or 'password' not in request.form:
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    email = request.form.get("email")
    password = request.form.get("password")

    # validate the email
    if len(email) < 1:
        statment = ('Please enter an email, <a href="/login"' +
                    ' style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    user = None

    #
    if not getUserID(email, DBSession()):
        statment = ('invalid email, <a href="/login"' +
                    ' style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    user = getUserDBInfo(getUserID(email, DBSession()), DBSession())

    # if there is a foreign account with this email (not internal)
    if not user.password_hash:
        statment = (
          'This email is not in our internal login system.<br><br>' +
          'it has a foreign account<br>(facebook or google), <br>' +
          '<a href="/login" style="font-size:39px">Try again here</a> ' +
          '<br>Or<br> head to ' +
          '<a href="/sign_up" style="font-size:39px">Sign up Form</a>' +
          ' to create an internal account')
        return render_template('status_message.html', statment=statment)

    # validate password
    if len(password) < 1:
        statment = ('Please enter a password, <a href="/login" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    # hash the given password
    hasher = hashlib.sha256()
    hasher.update(password.encode())
    hashed_password = hasher.hexdigest()

    # compare given password hash with the database saved hash
    if user.password_hash != hashed_password:
        statment = ('incorrect password, <a href="/login"' +
                    ' style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    # after success of the above operations,
    # we save the user info in the session and check that the user is logged
    session['signed'] = True
    session['provider'] = 'Internal'
    user_data_dict = {
                       'name':    user.name,
                       'email':   user.email,
                       'picture': user.picture,
                       'id':      user.id}

    session['user_data_dict'] = user_data_dict

    # redirect to homepage
    return redirect(url_for('index', _external=True))

# _________________________ End internal login view __________________________#
# _______________________ Start internal sign up view ________________________#


# internal sign up view
@app.route("/sign_up", methods=['POST', 'GET'])
def internal_sign_up():

    # if it is a GET request
    if request.method != 'POST':
        return render_template("sign_up.html")

    # check the post request body data form
    if not (request.form and
            'name' in request.form and
            'pic_url' in request.form and
            'email' in request.form and
            'verify_email' in request.form and
            'password' in request.form and
            'verify_password' in request.form and
            'sec_q' in request.form and
            'sec_a' in request.form):
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    name = request.form['name']
    pic_url = request.form['pic_url']
    email = request.form['email']
    verify_email = request.form['verify_email']
    password = request.form['password']
    verify_password = request.form['verify_password']
    sec_q = request.form['sec_q']
    sec_a = request.form['sec_a']

    # validate all the given data
    if len(name) < 1:
        statment = ('Please enter a name, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(email) < 1:
        statment = ('Please enter an email, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(verify_email) < 1:
        statment = ('Please confirm your email, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(password) < 1:
        statment = ('Please enter a password, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(verify_password) < 1:
        statment = ('Please confirm your password, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(sec_q) < 1:
        statment = ('Please enter a security question, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(sec_a) < 1:
        statment = ('Please enter an answer for the security question, ' +
                    '<a href="/sign_up" style="font-size:39px">' +
                    'Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(name) > 249:
        statment = ('Name is too long, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(pic_url) > 499:
        statment = ('picture URL is too long, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if email != verify_email:
        statment = ('Confirm email doesn\'t equal the first email, ' +
                    '<a href="/sign_up" style="font-size:39px">' +
                    'Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(email) > 99:
        statment = ('Email is too long , <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(password) > 65:
        statment = ('Password is too long, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(password) < 8:
        statment = ('Password is too short, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if password != verify_password:
        statment = ('Confirm password doesn\'t equal the first password, ' +
                    '<a href="/sign_up" style="font-size:39px">' +
                    'Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(sec_q) > 99:
        statment = ('security question is too long, <a href="/sign_up" ' +
                    'style="font-size:39px">Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(sec_a) > 99:
        statment = ('security answer is too long,<a href="/sign_up" ' +
                    'style="font-size:39px"> Try again here</a>')
        return render_template('status_message.html', statment=statment)

    if len(pic_url) < 10:
        pic_url = 'http://cdn.onlinewebfonts.com/svg/img_513928.png'

    user = None

    # hash the password
    hasher = hashlib.sha256()
    hasher.update(password.encode())
    hashed_password = hasher.hexdigest()

    # if we fond an email with hashed password
    #  then there is an account for this email in our internal login system
    # if we found an email without a password
    #  then this user has an account with google or facebook and
    #  we will create a internal account for him with the new password
    if getUserID(email, DBSession()):
        user_db_id = getUserID(email, DBSession())
        user = getUserDBInfo(user_db_id, DBSession())
        if user.password_hash and len(user.password_hash) > 0:
            statment = ('this email already has an account and a password, ' +
                        '<br><a href="/sign_up" style="font-size:39px">' +
                        'Try again here</a> Or <a href="/login" ' +
                        'style="font-size:39px">Log in here</a>')
            return render_template('status_message.html', statment=statment)

        # here the user has an account but not with the internal login system
        # a google or a facebook account (foreign account)
        # so if he is signed in we will save the password in the database
        # with the user row that has the email
        # but if he is not signed in then we will send an error messeage
        # showing that this email is associated with a user account
        # but not in our log in system
        # so if he is that user we will redirect him to the login form
        # to sign with the foreign account and
        # to fill the sign up form another time while he is signed

        if (
              'signed' in session and session['signed'] and
              session['user_data_dict']['email'] == email):

            user.password_hash = hashed_password

            db = DBSession()

            db.add(user)
            db.commit()
            db.close()

            return redirect(url_for('login'))

        statment = (
            'this email already has an account in this website <br>' +
            ' but not in our internal login system (facebook or google) <br>' +
            'if you want to create an account in our local system ' +
            'please log in to your foreign account and go back ' +
            'to this link <br>(<a href="https://localhost:5000/sign_up"' +
            ' style="font-size:39px">' +
            'https://localhost:5000/sign_up</a>) while you are logged in<br>' +
            ', <a href="/sign_up" style="font-size:39px">Try again here</a>' +
            ' Or <a href="/login" style="font-size:39px">Log in here</a>')

        return render_template('status_message.html', statment=statment)

    # Add the user to the data base

    user = User(name=name,
                email=email,
                password_hash=hashed_password,
                picture=pic_url,
                sec_q=sec_q,
                sec_a=sec_a)

    db = DBSession()

    db.add(user)
    db.commit()
    db.close()

    return redirect(url_for('login', _external=True))


# ________________________ End internal sign up view _________________________#

# ____________________________________________________________________________#
# ############### End  login and login-related views ##########################
# ____________________________________________________________________________#

# ____________________________________________________________________________#
# ####################### Start revoking views ################################
# ____________________________________________________________________________#

# ______________________ Start Facebook revoke function ______________________#


def revoke_fb(session, redirect_path):

    access_token = session['fb_access_token']

    url = ('https://graph.facebook.com/%s/permissions' %
           session['user_data_dict']['id'])

    params = {'access_token': access_token}

    result = requests.delete(url, params=params)

    del session['fb_access_token']
    if 'user_data_dict' in session:
        del session['user_data_dict']

    session['provider'] = 'None'
    session['signed'] = False

    return redirect(redirect_path)

# _______________________ End Facebook revoke function _______________________#
# _______________________ Start Google revoke function _______________________#


def revoke_google(session, redirect_path):
    if 'google_credentials' not in session:
        return redirect(redirect_path)

    credentials = google.oauth2.credentials.Credentials(
      **flask.session['google_credentials'])

    revoke = requests.post(
        'https://accounts.google.com/o/oauth2/revoke',
        params={'token': credentials.token},
        headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:

        del session['google_credentials']
        if 'user_data_dict' in session:
            del session['user_data_dict']
        session['signed'] = False
        session['provider'] = 'None'

        return redirect(redirect_path)
    else:
        del session['google_credentials']
        if 'user_data_dict' in session:
            del session['user_data_dict']
        session['signed'] = False
        session['provider'] = 'None'

        return redirect(redirect_path)

# ________________________ End Google revoke function ________________________#
# ______________________ Start internal revoke function ______________________#


def revoke_internal(redirect_path):

    if 'user_data_dict' in session:
        del session['user_data_dict']
    session['signed'] = False
    session['provider'] = 'None'

    return redirect(redirect_path)

# _______________________ End internal revoke function _______________________#
# __________________________ Start main revoke view __________________________#


# route to the appropriate revoke system (accorrding to the provider)
@app.route('/revoke')
def revoke():

    if 'redirect_uri_post_revoke' not in session:
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

        return redirect(redirect_path)


# ___________________________ End main revoke view ___________________________#

# ____________________________________________________________________________#
# ######################## End revoking views #################################
# ____________________________________________________________________________#


# ____________________________________________________________________________#
# #################### Start Static files routing views #######################
# ____________________________________________________________________________#

# Static files routers


# returns CSS files
@app.route('/css/<string:path>')
def get_css(path):
    try:
        return send_file((MD + 'templates/css/' + str(path)))
    except FileNotFoundError:
        return make_response("FileNotFoundError", 404)


# returns JavaScript files
@app.route('/js/<string:path>')
def get_js(path):
    try:
        return send_file((MD + 'templates/js/' + str(path)))
    except FileNotFoundError:
        return make_response("FileNotFoundError", 404)


# returns Images
@app.route('/img/<string:path>')
def get_img(path):
    try:
        return send_file((MD + 'templates/img/' + str(path)))
    except FileNotFoundError as e:
        print(e)
        return make_response("FileNotFoundError", 404)


# returns Font files
@app.route('/fonts/<string:path>')
def get_fonts(path):
    try:
        return send_file((MD + 'templates/fonts/' + str(path)))
    except FileNotFoundError:
        return make_response("FileNotFoundError", 404)

# ____________________________________________________________________________#
# ##################### End Static files routing views ########################
# ____________________________________________________________________________#


# ____________________________________________________________________________#
# ######################## Start main and CRUD views ##########################
# ____________________________________________________________________________#

# _____________________________ Start index view _____________________________#

@app.route('/')
@app.route('/index')
def index():

    db = DBSession()

    # retreive the required data from the database
    categories = db.query(Category)
    top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)
    latest_items = db.query(Item).order_by(desc(Item.id)).limit(8)

    # check if user is signed
    if 'signed' not in session:
        session['signed'] = False

    if session['signed']:
        template = render_template("index.html",
                                   categories=categories,
                                   items=latest_items,
                                   top_categories=top_cats,
                                   user_dict=session["user_data_dict"])

        db.close()

        return template

    template = render_template("index.html",
                               categories=categories,
                               items=latest_items,
                               top_categories=top_cats)

    db.close()

    return template

# ______________________________ End index view ______________________________#
# _____________________________ Start READ views _____________________________#


@app.route('/catalog/<string:cat_name>/items')
def view_category_items(cat_name):

    db = DBSession()

    # retreive the required data from the database
    top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

    category = None
    items = None
    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category" style="font-size:39px">' +
                    'Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    items = db.query(Item).filter_by(cat_id=category.id)

    if 'signed' not in session:
        session['signed'] = False

    if session['signed']:
        # renders the HTML template with the data
        template = render_template(
                            "category.html",
                            items=items,
                            categories=categories,
                            delete_url=(str(request.path)[:-6] + "/delete"),
                            edit_url=(str(request.path)[:-6] + "/edit"),
                            top_categories=top_cats,
                            category=category,
                            user_dict=session["user_data_dict"])
        db.close()

        return template

    # renders the HTML template with the data
    template = render_template("category.html",
                               items=items,
                               categories=categories,
                               delete_url=(str(request.path)[:-6] + "/delete"),
                               edit_url=(str(request.path)[:-6] + "/edit"),
                               top_categories=top_cats,
                               category=category)

    db.close()

    return template


# view certain item
@app.route('/catalog/<string:cat_name>/<string:item_name>')
def view_item(cat_name, item_name):

    db = DBSession()

    # retreive the required data from the database
    top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

    category = None
    item = None
    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    try:
        item = db.query(Item).filter_by(
                                cat_id=category.id, title=item_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have an item with the name "' +
                    item_name + '" in the category "' + cat_name +
                    '". <br> But you can <a href="/catalog/new-item"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    author = db.query(User).filter_by(id=item.author_id).one()

    if 'signed' not in session:
        session['signed'] = False

    if session['signed']:
        template = render_template("item.html",
                                   item=item,
                                   category=category,
                                   delete_url=(str(request.path) + "/delete"),
                                   edit_url=(str(request.path) + "/edit"),
                                   categories=categories,
                                   author=author,
                                   top_categories=top_cats,
                                   user_dict=session['user_data_dict'])

        db.close()

        return template

    template = render_template("item.html",
                               item=item,
                               category=category,
                               delete_url=(str(request.path) + "/delete"),
                               edit_url=(str(request.path) + "/edit"),
                               categories=categories,
                               author=author,
                               top_categories=top_cats,)

    db.close()

    return template

# ############################# JSON READ APIs ################################


# return a json dictionary containing the whole catalog
# (without items descriptions)
@app.route("/catalog/json")
def index_json():

    db = DBSession()

    # retreive the required data from the database
    categories = db.query(Category).all()

    result_dict = {}

    for c in categories:
        result_dict[c.name] = c.serialize
        result_dict[c.name]['items'] = {}

        try:
            items = db.query(Item).filter_by(cat_id=c.id)

            for i in items:
                result_dict[c.name]['items'][i.title] = i.serialize

                # not needed
                del result_dict[c.name]['items'][i.title]['category_id']
        except NoResultFound:
            pass

    db.close()

    response = make_response(json.dumps(result_dict), 200)
    response.headers['Content-Type'] = 'application/json'

    return response


# return a json dictionary containing all the items in a certain category
# (without items descriptions)
@app.route('/catalog/<string:cat_name>/json')
def category_json(cat_name):

    db = DBSession()

    category = None

    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    result_dict = {}

    result_dict[category.name] = category.serialize
    result_dict[category.name]['items'] = {}

    try:
        items = db.query(Item).filter_by(cat_id=category.id)

        for i in items:
            result_dict[category.name]['items'][i.title] = i.serialize

            # not needed
            del result_dict[category.name]['items'][i.title]['category_id']
    except NoResultFound:
        pass

    db.close()

    response = make_response(json.dumps(result_dict), 200)
    response.headers['Content-Type'] = 'application/json'

    return response


# return all attributes for a certain item
@app.route('/catalog/<string:cat_name>/<string:item_name>/json')
def item_json(cat_name, item_name):

    db = DBSession()

    category = None
    item = None

    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    try:
        item = db.query(Item).filter_by(title=item_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have an item with the name "' +
                    item_name + '" in the category "' + cat_name +
                    '". <br> But you can <a href="/catalog/new-item"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    result_dict = {}

    result_dict[item.title] = item.serialize_with_description

    db.close()

    response = make_response(json.dumps(result_dict), 200)
    response.headers['Content-Type'] = 'application/json'

    return response


# ______________________________ End READ views ______________________________#
# ____________________________ Start DELELTE views ___________________________#

@app.route("/catalog/<string:cat_name>/<string:item_name>/delete/<int:confrm>")
@app.route("/catalog/<string:cat_name>/<string:item_name>/delete")
def delete_item(cat_name, item_name, confrm=0):

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        return render_template('status_message.html', statment=statment)

    db = DBSession()

    # retreive the required data from the database
    top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

    category = None
    item = None

    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    try:
        item = db.query(Item).filter_by(
                                cat_id=category.id, title=item_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have an item with the name "' +
                    item_name + '" in the category "' + cat_name +
                    '". <br> But you can <a href="/catalog/new-item"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    author = db.query(User).filter_by(id=item.author_id).one()

    # check if the user is the item's author, if not
    # then he is not allowed to delete

    if session['user_data_dict']['email'] != author.email:
        statment = ('Only the item owner can delete it, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if confrm == 0:
        statment = 'Please confirm that you want to delete the item "'
        statment += item.title + '"'
        template = render_template('confirm.html',
                                   statment=statment,
                                   confirm_url=(str(request.path) + "/1"),
                                   categories=categories,
                                   user_dict=session['user_data_dict'],
                                   top_categories=top_cats)
        db.close()
        return template

    db.delete(item)
    db.commit()
    db.close()

    statment = ('The item was deleted successfully, ' +
                '<a href="/index" style="font-size:39px">Home page here</a>')
    return render_template('status_message.html', statment=statment)


# DELETE Category
@app.route("/catalog/<string:cat_name>/delete/<int:confirm>")
@app.route("/catalog/<string:cat_name>/delete")
def delete_category(cat_name, confirm=0):

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        return render_template('status_message.html', statment=statment)

    db = DBSession()

    # retreive the required data from the database
    top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

    category = None
    items = None
    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)
    try:
        items = db.query(Item).filter_by(cat_id=category.id)
    except NoResultFound:
        pass

    if confirm == 0:
        statment = ('Please confirm that you want to delete the category " ' +
                    '<font color="#008eff">' + category.name + '</font> "')
        template = render_template('confirm.html',
                                   statment=statment,
                                   confirm_url=(str(request.path) + "/1"),
                                   categories=categories,
                                   top_categories=top_cats)
        db.close()

        return template

    for i in items:
        db.delete(i)

    db.delete(category)
    db.commit()
    db.close()

    statment = ('The category was deleted successfully, ' +
                '<a href="/index" style="font-size:39px">Home page here</a>')
    return render_template('status_message.html', statment=statment)

# _____________________________ End DELELTE views ____________________________#


# Helping functions for validating user inputs
def validate_item(request, edited_item_id=None):

    try_again_url = '/catalog/new-item'

    edited_item = None

    db = DBSession()

    if edited_item_id:
        edited_item = db.query(Item).filter_by(id=edited_item_id).one()
        try_again_url = ('/catalog/' + str(edited_item.category.name) +
                         '/' + str(edited_item.title) + '/edit')

    # check the post request body data form
    if not (request.form and 'title' in request.form and
            'description' in request.form and 'category' in request.form):
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        db.close()
        return response

    title = request.form['title']
    description = request.form['description']
    category = request.form['category']

    # validate all the given data
    if len(title) < 1:

        statment = ('Please enter a title, ' +
                    '<a href="' + try_again_url +
                    '" style="font-size:39px">Try again here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if len(description) < 1:
        statment = ('Please enter a description, ' +
                    '<a href="' + try_again_url +
                    '" style="font-size:39px">Try again here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if len(title) > 99:
        statment = ('The title is too long, ' +
                    '<a href="' + try_again_url +
                    '" style="font-size:39px">Try again here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if len(description) > 999:
        statment = ('The description is too long, ' +
                    '<a href="' + try_again_url +
                    '" style="font-size:39px">Try again here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if not edited_item:
        if db.query(Item).filter_by(title=title).count() != 0:
            statment = ('An item with the same title already exists, ' +
                        '<a href="' + try_again_url +
                        '" style="font-size:39px">Try again here</a>')
            db.close()
            return render_template('status_message.html', statment=statment)

    else:
        if db.query(Item).filter_by(title=title).count() > 1:
            statment = ('An item with the same title already exists, ' +
                        '<a href="' + try_again_url +
                        '" style="font-size:39px">Try again here</a>')
            db.close()
            return render_template('status_message.html', statment=statment)

    item_cat = db.query(Category).filter_by(name=category).one()

    current_user_id = getUserID(session['user_data_dict']['email'], db, False)
    current_user = getUserDBInfo(current_user_id, db, False)

    new_item = None

    if edited_item is None:
        new_item = Item(title=title,
                        description=description,
                        category=item_cat,
                        author=current_user)

        # redirect to the new item page
        redirect_url = '/catalog/' + str(item_cat.name)
        redirect_url += '/' + str(new_item.title)

        db.add(new_item)
        db.commit()
    else:
        edited_item.title = title
        edited_item.description = description
        edited_item.category = item_cat

        # redirect to the edited item page
        redirect_url = '/catalog/' + str(edited_item.category.name)
        redirect_url += '/' + str(edited_item.title)

        db.add(edited_item)
        db.commit()

    db.close()

    return redirect(redirect_url)

# ____________________________ Start CREATE views ____________________________#


# make new category
@app.route("/catalog/new-category", methods=['POST', 'GET'])
def new_category():

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        return render_template('status_message.html', statment=statment)

    db = DBSession()

    # if it is a GET request
    if request.method != 'POST':

        # retreive the required data from the database
        categories = db.query(Category)
        top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)

        template = render_template("new_category.html",
                                   categories=categories,
                                   top_categories=top_cats,
                                   user_dict=session['user_data_dict'])

        db.close()

        return template

    if not request.form['name']:
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        db.close()
        return response

    name = request.form['name']

    if len(name) < 1:
        statment = ('Please enter a name, ' +
                    '<a href="/catalog/new-category" ' +
                    'style="font-size:39px">Try again here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if len(name) > 79:
        statment = ('The name is too long, ' +
                    '<a href="/catalog/new-category" ' +
                    'style="font-size:39px">Try again here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if db.query(Category).filter_by(name=name.title()).count() > 0:
        statment = ('A category with the same name already exists, ' +
                    '<a href="/catalog/new-category" ' +
                    'style="font-size:39px">Try again here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    new_cat = Category(name=name.title())

    db.add(new_cat)

    db.commit()

    db.close()

    return redirect('/catalog/' + str(name.title()) + '/items')


@app.route("/catalog/new-item", methods=['POST', 'GET'])
def new_item():

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        return render_template('status_message.html', statment=statment)

    # if it is a GET request
    if request.method != 'POST':

        current_cat_id = None
        current_cat = None

        db = DBSession()

        if request.args.get("cc"):
            current_cat_id = request.args.get("cc")

            try:
                current_cat = (db.query(Category)
                               .filter_by(id=current_cat_id).one())
            except NoResultFound:
                current_cat = None

        # retreive the required data from the database
        categories = db.query(Category)
        top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)

        template = render_template("new_item.html",
                                   categories=categories,
                                   current_cat=current_cat,
                                   top_categories=top_cats,
                                   user_dict=session['user_data_dict'])

        db.close()

        return template

    return validate_item(request)

# ______________________________ End CREATE views ____________________________#
# ______________________________START UPDATE VIEWS____________________________#


@app.route("/catalog/<string:cat_name>/edit", methods=['POST', 'GET'])
def edit_category(cat_name):

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        return render_template('status_message.html', statment=statment)

    category = None

    db = DBSession()

    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    # if it is a GET request
    if request.method != 'POST':

        # retreive the required data from the database
        categories = db.query(Category)
        top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)

        template = render_template("edit_category.html",
                                   categories=categories,
                                   old_cat=category,
                                   top_categories=top_cats,
                                   user_dict=session['user_data_dict'])

        db.close()

        return template

    if not request.form['name']:
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        db.close()
        return response

    name = request.form['name']

    if name.title() != category.name:

        if len(name) < 1:
            statment = ('Please enter a name, ' +
                        '<a href="/catalog/' + str(category.name) + '/edit" ' +
                        'style="font-size:39px">Try again here</a>')
            db.close()
            return render_template('status_message.html', statment=statment)

        if len(name) > 79:
            statment = ('The name is too long, ' +
                        '<a href="/catalog/' + str(category.name) + '/edit" ' +
                        'style="font-size:39px">Try again here</a>')
            db.close()
            return render_template('status_message.html', statment=statment)

        if db.query(Category).filter_by(name=name.title()).count() > 0:
            statment = ('A category with the same name already exists, ' +
                        '<a href="/catalog/' + str(category.name) + '/edit" ' +
                        'style="font-size:39px">Try again here</a>')
            db.close()
            return render_template('status_message.html', statment=statment)

    category.name = name.title()

    db.add(category)

    db.commit()

    db.close()

    return redirect('/catalog/' + str(name.title()) + '/items')


@app.route("/catalog/<string:cat_name>/<string:item_name>/edit",
           methods=['POST', 'GET'])
def edit_item(cat_name, item_name):

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        return render_template('status_message.html', statment=statment)

    category = None
    item = None

    db = DBSession()

    try:
        category = db.query(Category).filter_by(name=cat_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have a category named "' +
                    cat_name + '" . <br> But you can <a href=' +
                    '"/catalog/new-category"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    try:
        item = db.query(Item).filter_by(
                                cat_id=category.id, title=item_name).one()
    except NoResultFound:
        db.close()
        statment = ('🙁 looks like we don\'t have an item with the name "' +
                    item_name + '" in the category "' + cat_name +
                    '". <br> But you can <a href="/catalog/new-item"' +
                    ' style="font-size:39px">Create your own 😃</a>')
        return render_template('status_message.html', statment=statment)

    author = db.query(User).filter_by(id=item.author_id).one()

    # check if the user is the item's author, if not
    # then he is not allowed to edit

    if session['user_data_dict']['email'] != author.email:
        statment = ('Only the item owner can delete it, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    if session['user_data_dict']['email'] != author.email:
        statment = ('Only the item owner can edit it, ' +
                    '<a href="/login" style="font-size:39px">Log in here</a>')
        db.close()
        return render_template('status_message.html', statment=statment)

    # if it is a GET request
    if request.method != 'POST':

        # retreive the required data from the database
        categories = db.query(Category)
        top_cats = db.query(Category).order_by(desc(Category.id)).limit(3)

        template = render_template("edit_item.html",
                                   categories=categories,
                                   current_cat=category,
                                   old_item=item,
                                   top_categories=top_cats,
                                   user_dict=session['user_data_dict'])

        db.close()

        return template

    item_id = item.id
    db.close()
    return validate_item(request, item_id)

# _______________________________END UPDATE VIEWS_____________________________#

# ____________________________________________________________________________#
# ########################## End main and CRUD views ##########################
# ____________________________________________________________________________#

# #############################################################################
# ############################ End of VIEWS ###################################
# #############################################################################


# Run the server (over SSL) on localhost port 5000
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'

    app.debug = True
    # facebook login works only over https
    app.run()
