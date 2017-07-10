#!/usr/bin/env python
#
# application.py -- Project 'Item Catalog' - Fullstack Webdeveloper Nanodegree by Udacity
#
# This content id produced by David Duckwitz
# (c) 2017 by David Duckwitz (Project for Nanodegree - Udacity)
# You can take this for getting ideas, but please create your own script
# Thanks to Sources for help and inspiration while my Heart-attacks on finding Problems:
# --- Flask CSRF Protection: http://flask-wtf.readthedocs.io/en/stable/csrf.html
# --- Facebook Login: https://developers.facebook.com/docs/facebook-login/web and Udacity Tutorial
# --- Google Login: https://developers.google.com/api-client-library/python/guide/aaa_oauth

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base
from database_setup import User
from database_setup import Activities
from database_setup import Subcategories

import logging

from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask import flash
from flask import jsonify

from database_setup import Base
from database_setup import User
from database_setup import Activities
from database_setup import Subcategories

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "udacity-fullstack-itemcatalog"

# Connect to Database and create database session
engine = create_engine('sqlite:///categories.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# CSRF Security Features


def includeme(config):
    # previous configuration
    session_secret = os.environ.get('SESSION_SECRET', 'blockchainsafe')
    session_factory = SignedCookieSessionFactory(session_secret)
    config.set_session_factory(session_factory)

# Create a state token and Store it in the session for later validation
@app.route('/login')
def showLogin():
     """
    Loads Login Page.
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Is access token is valid ?
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Is access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Is access token is valid ?.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_token = credentials.access_token
    stored_gplus_id = login_session.get('gplus_id')
    if stored_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
     """
    Put data to Session
    """
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;'\
        'border-radius: 150px;'\
        '-webkit-border-radius: 150px;'\
        '-moz-border-radius: 150px;"> '
    if getUserID(login_session['email']) is None:
        createUser(login_session)
    flash("You are now logged in as %s" % login_session['username'])
    return output


# User Helper Functions

def createUser(login_session):
     """
    Creates the User.
    """
    newUser = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    try:
        access_token = login_session['access_token']
    except:
        flash('Current user not connected.')
        return redirect(url_for('showLogin'))
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        flash('Successfully disconnected.')
        return redirect(url_for('showLogin'))
    else:
        flash('Failed to revoke token for given user.')
        return redirect(url_for('activityList'))

# Facebook Login
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    ''' 
        Due to the formatting for the result from the server token exchange we have to 
        split the token first on commas and select the first index which gives us the key : value 
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '    
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    ''' 
        Disconnect the logged Facebook User.
    '''
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Main page
@app.route('/')
@app.route('/activities')
def activityList():
    ''' 
        Shows a list with activities
    '''
    activities = session.query(Activities).all()
    return render_template('activities.html', activities=activities, login_session=login_session)


# Create new activity
@app.route('/activities/new', methods=['GET', 'POST'])
def activityListNew():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Activities(name=request.form['name'],user_id=getUserID(login_session['email']))
        session.add(newItem)
        session.commit()
        flash("New activity added")
        return redirect(url_for('activityList'))
    else:
        return render_template('activities_new.html',login_session=login_session)

# Activities "make changes" page
# same as main page but with edit and delete buttons
@app.route('/activities/makechanges')
def activityListEdit():
    if 'username' not in login_session:
        return redirect('/login')
    activities = session.query(Activities).all()   
    return render_template('activities_makechanges.html',activities=activities,login_session=login_session)

# Main page for activity with items list
@app.route('/activities/<int:activity_id>')
def subCategory(activity_id):
    activity = session.query(Activities).filter_by(id=activity_id).one()
    if activity.user_id != login_session['user_id']:
        return flash('Not allowed for you.')
    subcategories = session.query(Subcategories).\
        filter_by(activity_id=activity_id).all()
    return render_template('activity.html',activity=activity,subcategories=subcategories,login_session=login_session)


# Items "make changes" page
# same as subCategory page but with edit/delete buttons
@app.route('/activities/<int:activity_id>/makechanges')
def subCategoryEdit(activity_id):
    if 'username' not in login_session:
        return redirect('/login')
    activity = session.query(Activities).filter_by(id=activity_id).one()
    if activity.user_id != login_session['user_id']:
        return flash('Not allowed for you.')
    subcategories = session.query(Subcategories).\
        filter_by(activity_id=activity_id).all()
    return render_template('activity_makechanges.html',activity=activity,subcategories=subcategories,login_session=login_session)


# Edit an item
@app.route(
    '/activities/<int:activity_id>/makechanges/<int:item_id>/edit',
    methods=['GET', 'POST'])
def itemEdit(activity_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Subcategories).filter_by(id=item_id).one()
    if editedItem.user_id != login_session['user_id']:
        return flash('Not allowed for you.')
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
            editedItem.user_id = getUserID(login_session['email'])
        session.add(editedItem)
        session.commit()
        flash("Item has been edited")
        return redirect(url_for('subCategoryEdit', activity_id=activity_id))
    else:
        return render_template('activity_edit.html',activity_id=activity_id,item_id=item_id,item=editedItem,login_session=login_session)


# Delete an item
@app.route(
    '/activities/<int:activity_id>/makechanges/<int:item_id>/delete',
    methods=['GET', 'POST'])
def itemDelete(activity_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Subcategories).filter_by(id=item_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return flash('Not allowed for you.')
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Item has been deleted!")
        return redirect(url_for('subCategoryEdit', activity_id=activity_id))
    else:
        return render_template('activity_delete.html',item=itemToDelete,item_id=item_id,activity_id=activity_id,login_session=login_session)


# Create a new item
@app.route('/activities/<int:activity_id>/new', methods=['GET', 'POST'])
def itemNew(activity_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Subcategories(
            name=request.form['name'],
            activity_id=activity_id,
            user_id=getUserID(login_session['email']))
        session.add(newItem)
        session.commit()
        flash("New activity added")
        return redirect(url_for('subCategory', activity_id=activity_id))
    else:
        return render_template('activity_new.html',activity_id=activity_id,login_session=login_session)

# Edit an activity
@app.route(
    '/activities/makechanges/<int:activity_id>/edit', methods=['GET', 'POST'])
def activityEdit(activity_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Activities).filter_by(id=activity_id).one()
    if editedItem.user_id != login_session['user_id']:
        return flash('Not allowed for you.')
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
            editedItem.user_id = getUserID(login_session['email'])
        session.add(editedItem)
        session.commit()
        flash("Activity has been edited")
        return redirect(url_for('activityListEdit'))
    else:
        return render_template('activityname_edit.html',activity_id=activity_id,activity=editedItem,login_session=login_session)

# Delete an activity
@app.route(
    '/activities/makechanges/<int:activity_id>/delete', methods=['GET', 'POST'])
def activityDelete(activity_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Activities).filter_by(id=activity_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return flash('Not allowed for you.')
    subItemsToDelete = session.query(Subcategories).\
        filter_by(activity_id=activity_id).all()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        for i in subItemsToDelete:
            session.delete(i)
        session.commit()
        flash("Activity has been deleted!")
        return redirect(url_for('activityListEdit'))
    else:
        return render_template('activities_delete.html',
                               activity=itemToDelete,
                               activity_id=activity_id,
                               login_session=login_session)


# Making an API Endpoint (GET Request)
@app.route('/activities/JSON')
def activitiesJSON():
    if 'username' not in login_session:
        return redirect('/login')
    items = session.query(Activities).all()
    return jsonify(ActivityList=[i.serialize for i in items])


# Making an API Endpoint (GET Request)
@app.route('/activities/JSON2')
def subcategoriesJSON():
    if 'username' not in login_session:
        return redirect('/login')
    items = session.query(Subcategories).all()
    return jsonify(ActivityList=[i.serialize for i in items])

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect('/login')
    else:
        flash("You were not logged in")
        return redirect("/login", code=302)

if __name__ == '__main__':
    app.secret_key = 'transcendence_secret_hash'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
