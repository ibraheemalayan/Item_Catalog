#!/usr/bin/env python3
# TODO Checklist
# make a public page and logged_in page
# make the json endpoints for every page on post methods
# make a README.md (copy it from logs analysis project)
# documenate your code
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

#Connect to Database and create database sessionmaker (DBSession)
engine = create_engine('sqlite:///Item_Catalog.db')
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
FB_APP_ID = json.loads(
              open(FB_CLIENT_SECRETS_FILE, 'r').read())['web']['app_id']
FB_APP_SECRET = json.loads(
                  open(FB_CLIENT_SECRETS_FILE, 'r').read())['web']['app_secret']

# Login helping methods

################################################################################
######################## Start of Login helping methods ########################
################################################################################

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

# ----- User Helper methods --------

# new user
def createUser(session,db,close_db = True):
    newUser = User(name=session['user_data_dict']['name'],
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
def getUserDBInfo(user_id,db,close_db = True):

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
def getUserID(email,db,close_db = True):
    try:
        user = db.query(User).filter_by(email=email).one()
        if close_db:
            db.close()
        return user.id
    except:
        if close_db:
            db.close()
        return None

################################################################################
######################### End of Login helping methods #########################
################################################################################


################################################################################
################################ Strat of VIEWS ################################
################################################################################


#______________________________________________________________________________#
################ Start of login and login-related views ########################
#______________________________________________________________________________#

#_________________________ Start Facebook login views _________________________#

# receives the access token from the javascript facebook login function
@app.route('/fbconnect', methods = ['POST'])
def fbconnect():

    #check if user is signed in and revoke if yes
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

    params = { 'grant_type': 'fb_exchange_token',
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

    params = { 'grant_type': 'fb_exchange_token',
               'access_token':      access_token,
               'fields':  'id,name,picture,email'}


    user_info = requests.get(user_info_url, params = params).json()

    # validate that user's information is received
    if 'error' in user_info:
        response = make_response(json.dumps('Error retreiving user info '), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # user_info dictionary Looks like:

    #{ 'id': '$$$$$$$$$$$$$$',
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
    #{ 'id': '$$$$$$$$$$$$$$',
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
    user_db_id = getUserID(session['user_data_dict']['email'],DBSession())
    if not user_db_id:
        user_db_id = createUser(session,DBSession())
    session['user_db_id'] = user_db_id

    # redirect to homepage
    return redirect( url_for('index') )

#__________________________ End Facebook login views __________________________#
#__________________________ Start Google login views __________________________#

# this view is called as the last step in our sign in with google system
# retreives user's information from google
@app.route('/get_google_user_info')
def get_google_user_info():

    #check if user is signed in and revoke if yes
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

    # get user's information
    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.token, 'alt': 'json'}

    data = requests.get(user_info_url, params=params)

    # validate that user's information is received
    if 'error' in data:
        return redirect(url_for('google_authorize'))

    json_user_data = data.json()

    # user_data_dict dictionary looks like >
    #"{'id': '114101744704852822727',
    #  'email': 'ibraheemalayan@gmail.com',
    #  'verified_email': True,
    #  'name': 'ibraheem Alayan',
    #  'given_name': 'ibraheem',
    #  'family_name': 'Alayan',
    #  'picture': 'https://lh3.googleusercontent.com/a-/AAuE7mBFRH0mLsQsnU3kqgFZ6l0_N6rHghZGYhMPdhCh5Q',
    #  'locale': 'en-GB'}"

    # removing unneeded pairs and reshaping the dictionary
    del json_user_data['id'] # we will replace with an id from our database based on the email
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
    user_db_id = getUserID(session['user_data_dict']['email'],DBSession())
    if not user_db_id:
        user_db_id = createUser(session,DBSession())
    session['user_data_dict']['id'] = user_db_id

    # redirect to homepage
    return redirect( url_for('index') )

# first google sign in view
@app.route('/google_authorize')
def google_authorize():

    #check if user is signed in and revoke if yes
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        session['redirect_uri_post_revoke'] = '/google_authorize'
        return redirect('/revoke')

    # Create flow instance to manage the OAuth2.0 Authorization Grant Flow steps
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

    #check if user is signed in and revoke if yes
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
    return redirect(url_for('get_google_user_info'))


#___________________________ End Google login views ___________________________#
#___________________________ Start Main login view ____________________________#

# this view returns the main login page with an anti-forgery state
@app.route("/login")
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    session['state'] = state
    response = make_response(render_template("login.html"))
    response.set_cookie('state', state)
    return response

#____________________________ End Main login view _____________________________#
#_______________________ Start Password recovery views ________________________#

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
        statment = ('Please enter a password ,' +
          '<a href="/login" style="font-size:39px">Try again here</a>')
        statment = ('invalid email ,' +
            '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    # retreive the user from the database
    user = getUserDBInfo(getUserID(email, db, False), db, False)

    db.close()

    # return the security question template
    return render_template('password_rec.html',email=user.email, sec_q=user.sec_q)

# handles the security question's answer given by the user
# decides if we update the password or don't
@app.route("/pr/<string:email>", methods=['POST'])
def update_password(email):

    #check if user is signed in and revoke if yes
    if 'signed' not in session:
        session['signed'] = False
    if session['signed']:
        revoke()

    # check the post request body data form
    if not email or 'sec_a' not in request.form or 'n_password' not in request.form:
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    sec_a = request.form['sec_a']
    new_password = request.form['n_password']

    # check the new password validity
    if len(new_password) < 1:
        statment = ('Please enter a password ,' +
          '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(new_password) > 65:
        statment = ('Password is too long ,' +
          '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(new_password) < 8:
        statment = ('Password is too short ,' +
          '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)
    db = DBSession()

    # retreive the user from the database
    if not getUserID(email, db, False):
        statment = ('invalid email ,' +
          '<a href="/login" style="font-size:39px">Try again here</a>')
        db.close()
        return  render_template('status_message.html',statment = statment)

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
        statment = ('Password was updated successfully ,' +
          '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    # if answer is incorrect return status template shows the result
    db.close()
    statment = ('Security answer is incorrect ,' +
      '<a href="/login" style="font-size:39px">Try again here</a>')
    return  render_template('status_message.html',statment = statment)

#_______________________ Start Password recovery views ________________________#
#_________________________ Start internal login view __________________________#

#TODO Limit user requests per minute
#TODO clean the styles.css
#TODO Add buttons and forms to create update delete items and categories

# receives post request from the main login page
@app.route("/internal_login", methods = ['POST'])
def internal_login():

    #check if user is signed in and revoke if yes
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
        statment = ('Please enter an email ,' +
            '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    user = None

    #
    if not getUserID(email,DBSession()):
        statment = ('invalid email ,' +
            '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    user = getUserDBInfo(getUserID(email,DBSession()), DBSession())

    # if there is a foreign account with this email (not internal)
    if not user.password_hash :
        statment = ('This email is not in our internal login system .<br><br>' +
          'it has a foreign account<br>(facebook or google), <br>' +
          '<a href="/login" style="font-size:39px">Try again here</a> '+
          '<br>Or<br> head to ' +
          '<a href="/sign_up" style="font-size:39px">Sign up Form</a>' +
          ' to create an internal account')
        return  render_template('status_message.html',statment = statment)

    # validate password
    if len(password) < 1:
        statment = ('Please enter a password ,' +
          '<a href="/login" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    # hash the given password
    hasher = hashlib.sha256()
    hasher.update(password.encode())
    hashed_password = hasher.hexdigest()

    # compare given password hash with the database saved hash
    if user.password_hash != hashed_password:
         statment = ('incorrect password ,' +
           '<a href="/login" style="font-size:39px">Try again here</a>')
         return  render_template('status_message.html',statment = statment)

    # after success of the above operations,
    # we save the user info in the session and check that the user is logged
    session['signed'] = True
    session['provider'] = 'Internal'
    user_data_dict = {
                       'name'    : user.name ,
                       'email'   : user.email ,
                       'picture' : user.picture ,
                       'id'      : user.id }

    session['user_data_dict'] = user_data_dict

    # redirect to homepage
    return redirect( url_for('index') )

#__________________________ End internal login view ___________________________#
#________________________ Start internal sign up view _________________________#

# internal sign up view
@app.route("/sign_up", methods = ['POST', 'GET'])
def internal_sign_up():

    # if it is a GET request
    if request.method != 'POST':
        return render_template("sign_up.html")

    # check the post request body data form
    if not ( request.form and  'name'            in request.form and
                           'pic_url'         in request.form and
                           'email'           in request.form and
                           'verify_email'    in request.form and
                           'password'        in request.form and
                           'verify_password' in request.form and
                           'sec_q'           in request.form and
                           'sec_a'           in request.form ) :
        response = make_response(json.dumps('Invalid form data.'), 406)
        response.headers['Content-Type'] = 'application/json'
        return response

    name            = request.form['name']
    pic_url         = request.form['pic_url']
    email           = request.form['email']
    verify_email    = request.form['verify_email']
    password        = request.form['password']
    verify_password = request.form['verify_password']
    sec_q           = request.form['sec_q']
    sec_a           = request.form['sec_a']

    # validate all the given data
    if len(name) < 1:
        statment = ('Please enter a name ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(email) < 1:
        statment = ('Please enter an email ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(verify_email) < 1:
        statment = ('Please confirm your email ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(password) < 1:
        statment = ('Please enter a password ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(verify_password) < 1:
        statment = ('Please confirm your password ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(sec_q) < 1:
        statment = ('Please enter a security question ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(sec_a) < 1:
        statment = ('Please enter an answer for the security question ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(name) > 249:
        statment = ('Name is too long ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(pic_url) > 499:
        statment = ('picture URL is too long ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if email != verify_email:
        statment = ('Confirm email doesn\'t equal the first email ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(email) > 99:
        statment = ('Email is too long  ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(password) > 65:
        statment = ('Password is too long ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(password) < 8:
        statment = ('Password is too short ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if password != verify_password:
        statment = ('Confirm password doesn\'t equal the first password ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(sec_q) > 99:
        statment = ('security question is too long ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

    if len(sec_a) > 99:
        statment = ('security question answer is too long ,' +
            '<a href="/sign_up" style="font-size:39px">Try again here</a>')
        return  render_template('status_message.html',statment = statment)

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
            statment = ('this email already has an account and a password ,' +
                '<br><a href="/sign_up" style="font-size:39px">' +
                'Try again here</a> Or ' +
                '<a href="/login" style="font-size:39px">Log in here</a>')
            return  render_template('status_message.html',statment = statment)

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

        if ( 'signed' in session and session['signed'] and
             session['user_data_dict']['email'] == email ):

            user.password_hash = hashed_password

            db = DBSession()

            db.add(user)
            db.commit()
            db.close()

            return redirect( url_for('login') )

        statment = ('this email already has an account in this website <br>' +
        ' but not in our internal login system (facebook or google) <br>' +
        'if you want to create an account in our local system ' +
        'please log in to your foreign account and go back to this link <br>' +
        '( <a href="https://localhost:5000/sign_up" style="font-size:39px">' +
        'https://localhost:5000/sign_up</a> ) while you are logged in <br>' +
        ',<a href="/sign_up" style="font-size:39px">Try again here</a>' +
        ' Or <a href="/login" style="font-size:39px">Log in here</a>')

        return  render_template('status_message.html',statment = statment)

    # Add the user to the data base

    user = User(name = name,
                email = email,
                password_hash = hashed_password,
                picture = pic_url,
                sec_q = sec_q,
                sec_a = sec_a)

    db = DBSession()

    db.add(user)
    db.commit()
    db.close()

    return redirect( url_for('login') )


#_________________________ End internal sign up view __________________________#

#______________________________________________________________________________#
################## End  login and login-related views ##########################
#______________________________________________________________________________#

#______________________________________________________________________________#
########################## Start revoking views ################################
#______________________________________________________________________________#

#_______________________ Start Facebook revoke function _______________________#

def revoke_fb(session, redirect_path):

    access_token = session['fb_access_token']

    url = ('https://graph.facebook.com/%s/permissions' %
            session['user_data_dict']['id'] )

    params = { 'access_token' : access_token }

    result = requests.delete(url, params = params)

    del session['fb_access_token']
    if 'user_data_dict' in session:
        del session['user_data_dict']

    session['provider'] = 'None'
    session['signed'] = False

    return redirect(redirect_path)

#________________________ End Facebook revoke function ________________________#
#________________________ Start Google revoke function ________________________#

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

        return redirect( redirect_path )

#_________________________ End Google revoke function _________________________#
#_______________________ Start internal revoke function _______________________#

def revoke_internal(redirect_path):

    if 'user_data_dict' in session:
        del session['user_data_dict']
    session['signed'] = False
    session['provider'] = 'None'

    return redirect( redirect_path )

#________________________ End internal revoke function ________________________#
#___________________________ Start main revoke view ___________________________#

# route to the appropriate revoke system ( accorrding to the provider )
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


#____________________________ End main revoke view ____________________________#

#______________________________________________________________________________#
########################### End revoking views #################################
#______________________________________________________________________________#


#______________________________________________________________________________#
####################### Start Static files routing views #######################
#______________________________________________________________________________#

# Static files routers

# returns CSS files
@app.route('/css/<string:path>')
def get_css(path):
    try:
        return send_file( ('templates\\css\\' + str(path).replace('/', '\\')))
    except FileNotFoundError:
        return make_response("FileNotFoundError",404)

# returns JavaScript files
@app.route('/js/<string:path>')
def get_js(path):
    try:
        return send_file( ('templates\\js\\' + str(path).replace('/', '\\')))
    except FileNotFoundError:
        return make_response("FileNotFoundError",404)

# returns Images
@app.route('/img/<string:path>')
def get_img(path):
    try:
        return send_file( ('templates\\img\\' + str(path).replace('/', '\\')))
    except FileNotFoundError as e:
        print(e)
        return make_response("FileNotFoundError",404)

# returns Font files
@app.route('/fonts/<string:path>')
def get_fonts(path):
    try:
        return send_file( ('templates\\fonts\\' + str(path).replace('/', '\\')))
    except FileNotFoundError:
        return make_response("FileNotFoundError",404)

#______________________________________________________________________________#
######################## End Static files routing views ########################
#______________________________________________________________________________#


#______________________________________________________________________________#
########################### Start main and CRUD views ##########################
#______________________________________________________________________________#


#______________________________ Start index view ______________________________#

@app.route('/')
@app.route('/index')
def index():

    db = DBSession()

    # retreive the required data from the database
    categories = db.query(Category)
    top_categories = db.query(Category).order_by(desc(Category.id)).limit(3)
    latest_items = db.query(Item).order_by(desc(Item.id)).limit(9)

    db.close()

    # check if user is signed
    if 'signed' not in session:
        session['signed'] = False

    if session['signed']:
        return render_template("index.html" ,
                               categories = categories,
                               items = latest_items,
                               top_categories = top_categories,
                               user_dict = session["user_data_dict"])

    return render_template("index.html" ,
                            categories = categories,
                            items = latest_items,
                            top_categories = top_categories)


#_______________________________ End index view _______________________________#
#______________________________ Start READ views ______________________________#


@app.route('/catalog/<string:cat_name>/items')
def view_category_items(cat_name):

    db = DBSession()

    # retreive the required data from the database
    top_categories = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

    category = None
    items = None
    try:
        category = db.query(Category).filter_by(name = cat_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/category_404.html", cat_name=cat_name)

    try:
        items = db.query(Item).filter_by(cat_id = category.id)
    except NoResultFound:
        db.close()
        return render_template("errors/category_empty.html", cat_name=cat_name)

    db.close()

    if 'signed' not in session:
        session['signed'] = False

    if session['signed']:
        # renders the HTML template with the data
        return render_template("category.html",
                               items = items,
                               categories = categories,
                               delete_url = (str(request.path)[:-6] + "/delete"),
                               edit_url = (str(request.path) + "/edit"),
                               top_categories = top_categories,
                               category = category,
                               user_dict = session["user_data_dict"])

    # renders the HTML template with the data
    return render_template("category.html",
                           items = items,
                           categories = categories,
                           delete_url = (str(request.path)[:-6] + "/delete"),
                           edit_url = (str(request.path) + "/edit"),
                           top_categories = top_categories,
                           category = category)


@app.route('/catalog/<string:cat_name>/<string:item_name>')
def view_item(cat_name, item_name):

    db = DBSession()

    # retreive the required data from the database
    top_categories = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

    category = None
    item = None
    try:
        category = db.query(Category).filter_by(name = cat_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/category_404.html", cat_name = cat_name)

    try:
        item = db.query(Item).filter_by(
                                cat_id = category.id, title = item_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/item_404.html",
                                cat_name = cat_name,
                                item_name = item_name)

    author = db.query(User).filter_by(id = item.author_id).one()
    db.close()

    if 'signed' not in session:
        session['signed'] = False

    if session['signed']:
        return render_template("item.html",
                               item = item,
                               category = category,
                               delete_url = (str(request.path) + "/delete"),
                               edit_url = (str(request.path) + "/edit"),
                               categories = categories,
                               top_categories = top_categories,
                               user_data_dict = session['user_data_dict'])

    return render_template("item.html",
                           item = item,
                           category = category,
                           delete_url = (str(request.path) + "/delete"),
                           edit_url = (str(request.path) + "/edit"),
                           categories = categories,
                           top_categories = top_categories)


#_______________________________ End READ views _______________________________#
#_____________________________ Start DELELTE views ____________________________#
#TODO complete those CRUD opreations

@app.route("/catalog/<string:cat_name>/<string:item_name>/delete/<int:confirm>")
@app.route("/catalog/<string:cat_name>/<string:item_name>/delete")
def delete_item(cat_name, item_name, confirm = 0):

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first ,' +
            '<a href="/login" style="font-size:39px">Log in here</a>')
        return  render_template('status_message.html',statment = statment)

    db = DBSession()

    # retreive the required data from the database
    top_categories = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

    category = None
    item = None
    try:
        category = db.query(Category).filter_by(name = cat_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/category_404.html", cat_name = cat_name)

    try:
        item = db.query(Item).filter_by(
                                cat_id = category.id, title = item_name).one()
    except NoResultFound:
        db.close()
        return render_template("errors/item_404.html",
                                cat_name = cat_name,
                                item_name = item_name)

    author = db.query(User).filter_by(id = item.author_id).one()

    # check if the user is the item's author ,if not
    # then he is not allowed to delete

    if session['user_data_dict']['email'] != author.email :
        statment = ('Only the item owner can delete it ,' +
            '<a href="/login" style="font-size:39px">Log in here</a>')
        db.close()
        return  render_template('status_message.html',statment = statment)


    if confirm == 0:
        statment = 'Please confirm that you want to delete the item "'
        statment += item.title + '"'
        db.close()
        return render_template( 'confirm.html',
                                statment = statment,
                                confirm_url = (str(request.path) + "/1"),
                                categories = categories,
                                top_categories = top_categories )

    db.delete(item)
    db.commit()
    db.close()

    statment = ('The item was deleted successfully ,' +
        '<a href="/index" style="font-size:39px">Home page here</a>')
    return  render_template('status_message.html',statment = statment)

# DELETE Category
@app.route("/catalog/<string:cat_name>/delete/<int:confirm>")
@app.route("/catalog/<string:cat_name>/delete")
def delete_category(cat_name, confirm = 0):

    if 'signed' not in session or not session['signed']:
        statment = ('Please log in first ,' +
            '<a href="/login" style="font-size:39px">Log in here</a>')
        return  render_template('status_message.html',statment = statment)

    db = DBSession()

    # retreive the required data from the database
    top_categories = db.query(Category).order_by(desc(Category.id)).limit(3)
    categories = db.query(Category)

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
        pass

    if confirm == 0:
        statment = 'Please confirm that you want to delete the category " <font color = "#008eff">'
        statment += category.name + '</font> "'
        db.close()
        return render_template( 'confirm.html',
                                statment = statment,
                                confirm_url = (str(request.path) + "/1"),
                                categories = categories,
                                top_categories = top_categories )

    for i in items:
        db.delete(i)

    db.delete(category)
    db.commit()
    db.close()

    statment = ('The category was deleted successfully ,' +
        '<a href="/index" style="font-size:39px">Home page here</a>')
    return  render_template('status_message.html',statment = statment)

#_____________________________ Start DELELTE views ____________________________#


#______________________________________________________________________________#
############################ End main and CRUD views ###########################
#______________________________________________________________________________#

################################################################################
############################# End of VIEWS #####################################
################################################################################

#Run
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    # facebook login works only over https
    app.run(host = '0.0.0.0', port = 5000, ssl_context='adhoc')
