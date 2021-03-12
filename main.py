import base64
import hashlib
import random

import requests
from flask import Flask, render_template, request, session, make_response
from google.cloud import datastore
from datetime import timedelta, timezone, tzinfo
import datetime
import json
import bcrypt
import os
import pytz
import win32gui

client = datastore.Client()
utc = pytz.UTC
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['PERMANENT_SESSION_LEFETIME'] = timedelta(hours=1)


# add event
@app.route('/add', methods=['get', 'post'])
def add():
    # check if year satisfies the format(year should be 4 digits or yearless)
    year = request.args.get('year')
    if 0 < len(year) < 4:
        return init()
    kind = 'event'
    # The name/ID for the new entity
    name = datetime.datetime.now().strftime('%H:%M:%S.%f')
    # The Cloud Datastore key for the new entity
    task_key = client.key(kind, name)
    # Prepares the new entity
    userId = get_userId()
    task = datastore.Entity(key=task_key)
    task['userId'] = userId
    task['name'] = request.args.get('name')
    task['year'] = year
    task['month'] = request.args.get('month')
    task['date'] = request.args.get('date')
    task['description'] = request.args.get('description')
    # Saves the entity
    client.put(task)
    return init()


# -----------------------------------------------------------------
# initialize the main page
@app.route('/init', methods=['get', 'post'])
def init():
    userId = get_userId()
    query = client.query(kind='event')
    query.add_filter('userId', '=', userId)
    results = list(query.fetch())
    res = []
    for result in results:
        dict = {}
        is_yearless = False
        year = result['year']
        month = result['month']
        date = result['date']
        cur_date = datetime.datetime.now()
        # check if it is a yearless event
        # if yearless, add a year to the event, mark it as yearless
        if year == '':
            year = str(cur_date.year)
            is_yearless = True
        # transform event date from string to date
        str_date = year+'-'+month+'-'+date
        event_date = datetime.datetime.strptime(str_date,'%Y-%m-%d')
        # compare the event date with current date
        # if the event has pasted
        if event_date<cur_date:
            # if it is a yearless event, leave it
            if is_yearless:
                continue
            # otherwise delete it
            else:
                client.delete(result.key)
                continue
        # get time differnce for ETA
        hours = int(((event_date - cur_date).seconds) / 3600)
        days = (event_date - cur_date).days
        eta = str(days)+'days'+str(hours)+'hours'
        # pack data
        dict['year'] = year
        dict['name'] = result['name']
        dict['month'] = month
        dict['date'] = date
        dict['eta'] = eta
        res.append(dict)
    res.sort(key=lambda x:(eval(x['year']),eval(x['month']),eval(x['date'])))
    return json.dumps(res)

# ------------------------------------------------------------------------------
# check detail of event
@app.route('/check', methods=['get', 'post'])
def check():
    userId = get_userId()
    query = client.query(kind='event')
    query.add_filter('name', '=', request.args.get('name'))
    query.add_filter('userId', '=', userId)
    results = list(query.fetch())
    dict = {}
    dict['description'] = results[0]['description']
    dict['time'] = results[0]['year'] + '-' + results[0]['month'] + '-' + results[0]['date']
    dict['name'] = results[0]['name']
    return json.dumps(dict)


# --------------------------------------------------------------------------
# delete events
@app.route('/del', methods=['get', 'post'])
def delete():
    userId = get_userId()
    query = client.query(kind='event')
    query.add_filter('name', '=', request.args.get('name'))
    query.add_filter('userId', '=', userId)
    result = list(query.fetch())[0]
    key = result.key
    client.delete(key)
    return init()


# -------------------------------------------------------------------------------
# login
@app.route('/login', methods=['get', 'post'])
def login():
    # get userinfo from front
    username = request.form.get('username')
    password = request.form.get('password')
    if (password == None):
        return render_template('index.html')
    encoded = password.encode('utf-8')

    # get user data from datastore
    query = client.query(kind='user')
    query.add_filter('username', '=', username)
    results = list(query.fetch())
    # compare userInfo, if match, store userId in session and go to main page
    if len(results) == 0:
        return render_template('login_fail.html')
    else:
        encrypted = results[0]['password']
        # check encrypted password
        if bcrypt.checkpw(encoded, encrypted):
            # generate sessionId
            sessionId = ''.join([str(random.randint(0, 9)) for i in range(9)])
            # store session and userInfo
            set_session(sessionId, results[0]["userId"])
            # set cookie
            response = make_response(render_template("index.html"))
            response.set_cookie("sessionId", sessionId, max_age=7200)
            return response
        else:
            return render_template('login_fail.html')


# --------------------------------------------------------------
@app.route('/register', methods=['get', 'post'])
def register():
    # get userinfo from front
    username = request.form.get('username')
    password = request.form.get('password')
    if password == None:
        return render_template('index.html')
    password = password.encode('utf-8')
    # get id for new user
    id = get_new_id()
    kind = 'user'
    # The name/ID for the new entity
    name = datetime.datetime.now().strftime('%H:%M:%S.%f')
    # The Cloud Datastore key for the new entity
    task_key = client.key(kind, name)
    # Prepares the new entity
    task = datastore.Entity(key=task_key)
    task['userId'] = id
    task['username'] = username
    # save encrypted password
    task['password'] = bcrypt.hashpw(password, bcrypt.gensalt(10))
    # Saves the entity
    client.put(task)
    # generate sessionID
    sessionId = ''.join([str(random.randint(0, 9)) for i in range(9)])
    set_session(sessionId, id)
    # set cookie
    response = make_response(render_template("index.html"))
    response.set_cookie("sessionId", sessionId, max_age=7200)
    return response


# ------------------------------------------------------------------------
@app.route('/go_register')
def go_register():
    return render_template('register.html')


@app.route('/logout')
def logout():

    # delete session on datastore
    query = client.query(kind='session')
    query.add_filter('sessionId', '=', request.cookies.get('sessionId'))
    result = list(query.fetch())[0]
    key = result.key
    client.delete(key)
    # force cookie to expire
    response = make_response(render_template("logout.html"))
    response.set_cookie("sessionId", '', expires=-1)
    response.set_cookie("state", '', expires=-1)
    response.set_cookie("nonce", '', expires=-1)
    return response


@app.route('/')
def index():
    # if no cookie(user not logged in)
    if request.cookies.get("sessionId") == None:
        # prepare the url for oauth2 login
        state = hashlib.sha256(os.urandom(1024)).hexdigest()
        nonce = ''.join([str(random.randint(0, 9)) for i in range(9)])
        url = "https://accounts.google.com/o/oauth2/v2/auth?" \
              "response_type=code&client_id=168782460237-f2i4usn6m9a0iggtasrqcqbjqijigr1t.apps.googleusercontent.com&" \
              "scope=openid%20email&state=" + state + "&nonce=" + nonce + "&redirect_uri=https%3A//gchen43-event-manager" \
                                                                          ".ue.r.appspot.com/oauth"
        # store state and nonce in cookies for verifying
        response = make_response(render_template("login.html", url=url))
        response.set_cookie("nonce", nonce, max_age=3600)
        response.set_cookie("state", state, max_age=3600)
        return response
    else:
        return render_template("index.html")


@app.route('/oauth')
def oauth():
    state = request.args.get('state')
    if (state == None):
        return render_template('index.html')
    # verify state
    if state != request.cookies.get('state'):
        return "state mismatch!"
    code = request.args.get("code")
    # get secret from datastore
    client_secret = get_secret()
    url = "https://www.googleapis.com/oauth2/v4/token"
    data = {"code": code,
            "client_id": "168782460237-f2i4usn6m9a0iggtasrqcqbjqijigr1t.apps.googleusercontent.com",
            "client_secret": client_secret,
            "redirect_uri": "https://gchen43-event-manager.ue.r.appspot.com/oauth",
            "grant_type": "authorization_code"}
    response = requests.post(url, data)
    id_token = response.json()['id_token']
    # decrypt token and get user email address
    _, body, _ = id_token.split('.')
    body += '=' * (-len(body) % 4)
    claims = json.loads(base64.urlsafe_b64decode(body.encode('utf-8')))
    # verify nonce
    if claims['nonce'] != request.cookies.get('nonce'):
        return "nonce mismatch"
    email = claims['email']

    # search the user with email address
    query = client.query(kind='user')
    query.add_filter('email', '=', email)
    results = list(query.fetch())
    id = 0
    # if the user doesnt exist, create one
    if len(results) == 0:
        id = get_new_id()
        kind = 'user'
        name = datetime.datetime.now().strftime('%H:%M:%S.%f')
        task_key = client.key(kind, name)
        task = datastore.Entity(key=task_key)
        task['userId'] = id
        task['email'] = email
        client.put(task)
    else:
        id = results[0]['userId']
    # set session
    sessionId = ''.join([str(random.randint(0, 9)) for i in range(9)])
    set_session(sessionId, id)
    # set cookie
    response = make_response(render_template("index.html"))
    response.set_cookie("sessionId", sessionId, max_age=7200)
    return response


def set_session(sessionId, userId):
    expire = datetime.datetime.now()
    expire += datetime.timedelta(hours=1)
    # store session to datastore
    kind = 'session'
    name = datetime.datetime.now().strftime('%H:%M:%S.%f')
    task_key = client.key(kind, name)
    task = datastore.Entity(key=task_key)
    task['sessionId'] = sessionId
    task['expire'] = expire
    task['userId'] = userId
    # Saves the entity
    client.put(task)


def get_userId():
    sessionId = request.cookies.get('sessionId')
    query = client.query(kind='session')
    query.add_filter('sessionId', '=', sessionId)
    results = list(query.fetch())
    # check if the session is expired
    if results[0]['expire'].replace(tzinfo=timezone.utc) > utc.localize(datetime.datetime.now()):
        return results[0]['userId']
    else:
        logout()


def get_secret():
    query = client.query(kind='secrete')
    result = list(query.fetch())[0]
    return result['client_secret']


def get_new_id():
    query = client.query(kind='user')
    results = list(query.fetch())
    return len(results)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
