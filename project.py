#!/usr/bin/env python3
# TODO Checklist
# implement the login with facebook and google and your own login
# hash passwords and use https
# make a simple html for a the index page and other pages
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

# Views

# @app.route("/login")
# def login():
#     return render_template("login.html")

@app.route('/')
def index():
    db = DBSession()
    categories = db.query(Category).all()
    latest_items = db.query(Item).order_by(desc(Item.id)).limit(5)

    db.close()

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
