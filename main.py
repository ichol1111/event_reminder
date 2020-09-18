from flask import Flask,render_template,request
from google.auth.transport import requests
from google.cloud import datastore
import datetime
import json
import google.oauth2.id_token

client = datastore.Client()
firebase_request_adapter = requests.Request()

app = Flask(__name__)

@app.route('/add',methods=['get'])
def add():
    kind = 'event'
    # The name/ID for the new entity
    name = datetime.datetime.now().strftime('%H:%M:%S.%f')
    # The Cloud Datastore key for the new entity
    task_key = client.key(kind, name)

    # Prepares the new entity
    task = datastore.Entity(key=task_key)
    task['name'] = request.args.get('name')
    task['year']= request.args.get('year')
    task['month'] = request.args.get('month')
    task['date'] = request.args.get('date')
    # Saves the entity
    client.put(task)
    return init()

@app.route('/init',methods=['POST'])
def init():
    query = client.query(kind='event')
    results = list(query.fetch())
    res = []
    for r in results:
        dict = {}
        dict['name'] = r['name']
        dict['year'] = r['year']
        dict['month'] = r['month']
        dict['date'] = r['date']
        res.append(dict)
    res.sort(key=lambda x:(x['year'],x['month'],x['date']))
    return json.dumps(res)

@app.route('/')
def index():
    # Verify Firebase auth.
    id_token = request.cookies.get("token")
    error_message = None
    claims = None
    times = None

    if id_token:
        try:
            # Verify the token against the Firebase Auth API. This example
            # verifies the token on each page load. For improved performance,
            # some applications may wish to cache results in an encrypted
            # session store (see for instance
            # http://flask.pocoo.org/docs/1.0/quickstart/#sessions).
            claims = google.oauth2.id_token.verify_firebase_token(
                id_token, firebase_request_adapter)


        except ValueError as exc:
            # This will be raised if the token is expired or any other
            # verification checks fail.
            error_message = str(exc)

    return render_template(
        'index.html',
        user_data=claims, error_message=error_message)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)