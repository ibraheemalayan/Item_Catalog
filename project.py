#!/usr/bin/env python3
# TODO Checklist
# implement the login with facebook and google and your own login
# hash passwords
# make a public page and logged_in page
# make a function that returns true if user is signed in and false if not then use it in implementing the CRUD pages
# make the json endpoints for every page on post methods
# make a sign up form
# make a login page that shows the 3 sign in ways
# make a script that fills the database
# make a README.md (copy it from logs analysis project)
# documenate your code
# style your templates
# Follow PEP 8
# check that you meet the requirements here > https://review.udacity.com/#!/rubrics/2008/view

from flask import (Flask, render_template, request, session, request,
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
    return user.id


def getUserDBInfo(user_id,db):
    try:
        user = db.query(User).filter_by(id=user_id).one()
        return user
    except NoResultFound:
        return None


def getUserID(email,db):
    try:
        user = db.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Login Back-end Views

@app.route('/get_google_user_info')
def get_google_user_info():
    if 'google_credentials' not in session:
      return redirect('google_authorize')

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
    if session['signed']:
        return redirect('/revoke')
        # TODO add a parameter to the revoke call to specify where to redirect after revoke
        # TODO HERE call revoke with a redirect_uri as this function

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
    if session['signed']:
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
    return render_template("login.html")

@app.route("/glogin")
def google_login():
    return redirect( url_for('google_authorize') )

@app.route("/flogin")
def facebook_login():
    return render_template("login.html")

@app.route("/ilogin", methods = ['POST'])
def internal_login():
    return render_template("login.html")

@app.route("/sign_up")
def internal_sign_up():
    return render_template("login.html")

# Revoking functions

def revoke_google(session):
    if 'google_credentials' not in session:
      return redirect( url_for('index') )

    credentials = google.oauth2.credentials.Credentials(
      **flask.session['google_credentials'])

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
        params={'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:

        del session['google_credentials']
        del session['user_data_dict']
        session['signed'] = False
        session['provider'] = 'None'

        return redirect('/?flash=SO')
    else:
        del session['google_credentials']
        del session['user_data_dict']
        session['signed'] = False
        session['provider'] = 'None'

        return('<h1>An error occurred while revoking credentials.</h1>')


@app.route('/revoke')
def revoke():
    if session['signed']:
        if session['provider'] == 'Google':
            return revoke_google(session)
    else:
        session['signed'] = False
        session['provider'] = 'None'
        del session['user_data_dict']

        return redirect( url_for('index') )


# Views

@app.route('/')
def index():
    db = DBSession()
    categories = db.query(Category).all()
    latest_items = db.query(Item).order_by(desc(Item.id)).limit(5)

    db.close()

    if 'signed' not in session:
        session['signed'] = None

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
