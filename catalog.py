#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Latest Revision 9/15/17

A web page/app for a talent agency allowing clients to manage profiles

@author: Tripp
"""

from flask import Flask, render_template, flash, request, abort,\
session as login_session, redirect, url_for, jsonify, send_from_directory
from flask_uploads import UploadSet, IMAGES, configure_uploads,\
patch_request_class
#from siteforms import ContactForm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Make, Photo, Model, User
import random, string
import os
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from siteforms import EditModel, PhotoForm, NewModel

#Pull in the client secret key for Google Sign In
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

#Connect to SQL database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()

app = Flask(__name__)

#Set the destination for user photo uploads
app.config['UPLOADED_PHOTOS_DEST'] = 'static/img'

#Create parameters for uploads, patch max upload size
photos = UploadSet('photos', IMAGES)
configure_uploads(app, (photos))
patch_request_class(app)


@app.route('/')
@app.route('/index')
def homepage():

#Create list of 6 most recently added cars
    makes = session.query(Make).all()
    latest_model_list = session.query(Model).\
                        order_by(Model.created.desc()).limit(6)
    
#Check if user is signed in
    if 'email' in login_session:
        user = session.query(User).\
               filter_by(email = login_session['email']).first()

        return render_template("index.html", user = user, makes=makes,
                               latest_model_list=latest_model_list)
    else:
        return render_template("index.html", user = None, makes=makes,
                               latest_model_list=latest_model_list)

@app.route('/login', methods = ['GET', 'POST'])
def loginpage():

    if request.method == 'GET':

        #Generate state token for CSRF check
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)\
                for x in range(32))

        login_session['state'] = state

        return render_template("login.html", STATE=state )
 
@app.route('/fbconnect', methods = ['POST'])
def fbconnect():

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data
    
    #Open stored keys
    app_id = json.loads(open('fb_client_secrets.json', 'r').\
                        read())['web']['app_id']

    app_secret = json.loads(open('fb_client_secrets.json', 'r').\
                        read())['web']['app_secret']

    #Get access token
    url = "https://graph.facebook.com/v2.10/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s"\
    % (app_id ,app_secret, code)

    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    token = result['access_token']

    url = "https://graph.facebook.com/v2.10/me?access_token=%s&fields=id,name,picture,email" % token

    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    #Create user session
    login_session['username'] = result['name']
    login_session['picture'] = result['picture']['data']['url']
    login_session['email'] = result['email']
    login_session['provider'] = 'facebook'

    #Create user
    newuser = User(email = login_session['email'], id = int(result['id']))

    if session.query(User).filter_by(email = newuser.email).first() is None:

        session.add(newuser)

        session.commit()
    
    login_session['id'] = newuser.id
             
    return 'sucess'


@app.route('/gconnect', methods = ['POST'])
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
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        
        response = make_response\
        (json.dumps('Current user is already connected.'),200)
 
        response.headers['Content-Type'] = 'application/json'

        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['provider'] = 'google'
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    
    #Create user session
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    newuser = User(email = login_session['email'])

    if session.query(User).filter_by(email = newuser.email).first() is None:

        session.add(newuser)
        session.commit()
       
    newuser = session.query(User).\
              filter_by(email = login_session['email']).first()

    login_session['id'] = newuser.id

    return 'success'
               
@app.route('/gdisconnect')
def gdisconnect():

    provider = login_session.get('provider')

    if provider is None:

        login_session.clear()


        resp = make_response(redirect(url_for('homepage')))

        #Fixes error in Safari caused by pre-fetch of cached pages
        resp.headers['Cache-Control']=\
        'no-cache, no-store, must-revalidate, post-check=0, pre-check=0'

        return resp

    if provider == 'google':

        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'\
        % login_session['access_token']
        
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]

        if result['status'] == '200':

            login_session.clear()


            resp = make_response(redirect(url_for('homepage')))

            #Fixes error in Safari caused by pre-fetch of cached pages
            resp.headers['Cache-Control']=\
            'no-cache, no-store, must-revalidate, post-check=0, pre-check=0'

            return resp

        else:

            response = make_response\
            (json.dumps('Failed to revoke token for given user.', 400))
            
            response.headers['Content-Type'] = 'application/json'
            return response

    if provider == 'facebook':

        login_session.clear()

        resp = make_response(redirect(url_for('homepage')))

        #Fixes error in Safari caused by pre-fetch of cached pages
        resp.headers['Cache-Control']=\
        'no-cache, no-store, must-revalidate, post-check=0, pre-check=0'

        return resp


@app.route('/<make>')
def selectedpage(make):

    #Create list of vehicle makers
    makes = session.query(Make).all()
    
    #store currently selected make
    selected = session.query(Make).filter_by(name=make).first()

    if 'email' in login_session:
 
        user = session.query(User).\
               filter_by(email=login_session['email']).first()

        return render_template\
            ("selected.html", user = user, makes=makes, selected=selected)
    else:
        return render_template\
            ("selected.html", makes=makes, selected=selected)


@app.route('/talent/profile/<int:car_id>')
def itempage(car_id):

   model = session.query(Model).filter_by(id=car_id).first()

   if 'email' in login_session:
 
        user = session.query(User).\
               filter_by(email=login_session['email']).first()

        return render_template("item.html", model=model, user=user)

   return render_template("item.html", model=model)


@app.route('/<int:car_id>/delete')
def deletecar(car_id):

    car = session.query(Model).filter_by(id=car_id).first()

    #Remove old photo from system
    if os.path.isfile('static/img/uploads/' + car.photo[0].path)\
    and car.photo[0].path != 'nophoto.png':
                             
            os.remove('static/img/uploads/' + car.photo[0].path)

    #Delete DB entry
    session.delete(car)
    session.commit()

    return redirect(url_for('homepage'))


@app.route('/<int:car_id>/edit', methods = ['GET','POST'])
def edititem(car_id):   

    model = session.query(Model).filter_by(id=car_id).first()

    #Exit if not a current user session or session is not valid
    if 'email' not in login_session:

        return redirect(url_for('itempage', car_id=car_id))

    else:

        if not session.query(User).\
        filter_by(email=login_session['email']).first():
   
            return redirect(url_for('itempage', car_id=car_id))

    user=session.query(User).filter_by(email=login_session['email']).first()

    #Populate form
    form = EditModel(obj=model, color=model.color, name=model.name, \
                    year=model.year, mileage=model.mileage,\
                    trim=model.trim, accident=model.accident,\
                    condition=model.condition)

    if request.method == 'POST' and form.validate():

        model.color=form.color.data
        model.mileage=form.mileage.data
        model.year=form.year.data
        model.accident=form.history.data
        model.name=form.name.data
        model.trim=form.trim.data
        model.condition=form.condition.data
        model.description=form.description.data

        session.commit()      
        
        return redirect(url_for('itempage', car_id=model.id))

    return render_template('edititem.html', form=form, model=model, user=user)

@app.route('/newcar', methods = ['GET','POST'])
def newcar():   
    
    #Check for current user session
    if 'email' not in login_session:

        return redirect(url_for('homepage'))

    else:

        if not session.query(User).\
        filter_by(email=login_session['email']).first():
   
            return redirect(url_for('homepage'))

    user=session.query(User).filter_by(email=login_session['email']).first()

    form = NewModel()
    model = Model()

    if request.method == 'POST' and form.validate():
        
        makename=form.make.data
        
        if session.query(Make).filter_by(name=makename).first():
            model.make = session.query(Make).filter_by(name=makename).first()
        else:
            make = Make(name=makename)
            session.add(make)
        
        model.color=form.color.data
        model.mileage=form.mileage.data
        model.year=form.year.data
        model.accident=form.history.data
        model.name=form.name.data
        model.condition=form.condition.data
        model.description=form.description.data
        photo = Photo(model=model, path='nophoto.png')
        
        session.add(photo)
        session.add(model)
        session.commit()      
        
        return redirect(url_for('itempage', car_id=model.id))

    return render_template('newitem.html', form=form, model=model, user=user)

@app.route('/upload/<int:car_id>', methods = ['GET', 'POST'])
def uploadphoto(car_id):
    
    if 'email' not in login_session:

        return redirect(url_for('homepage'))

    else:

        if not session.query(User).\
        filter_by(email=login_session['email']).first():
   
            return redirect(url_for('homepage'))
    
    form = PhotoForm()
    model = session.query(Model).filter_by(id=car_id).first()

    if request.method == 'POST' and form.photo.data:

        filename = photos.save(form.photo.data, folder = 'uploads')
        oldphoto = session.query(Photo).filter_by(model_id=car_id).first()
        newphoto = Photo(path=filename[8::], model=model)

        #delete photo from DB
        session.delete(oldphoto)
        session.add(newphoto)
        
        session.commit()

        #Remove old photo from system
        if os.path.isfile('static/img/uploads/' + oldphoto.path)\
        and oldphoto.path != 'nophoto.png':

            os.remove('static/img/uploads/' + oldphoto.path)

        flash("Photo Saved")

        return redirect(url_for('itempage', car_id=car_id))

    if request.method == 'GET':

        return render_template('uploadphoto.html', car_id=car_id, form=form)
    
@app.route('/catalog.json')
def catalogjson():

    makes = session.query(Make).all()

    allcars = {}
    allcars['Makes']=[]

    for make in makes:

        allcars['Makes'].append(make.serialize)

    return jsonify(allcars)

if __name__=='__main__':
    app.debug = True
    app.secret_key = os.urandom(24)
    app.run(host = '0.0.0.0', port = 5000)