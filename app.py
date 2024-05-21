from flask import Flask

from authlib.integrations.flask_client import OAuth
from flask import url_for, redirect, session
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = "secret"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# define login decorator
def login_required(f):
    @wraps(f)
    def check_login(*args, **kwargs):
        if not session.get("email", None):
            return "no user connected"
        return f(*args, **kwargs)
    return check_login


@app.route('/')
@login_required
def hello():
    email = dict(session).get("email", None)
    session.pop("email")
    return f"hello world {email}"





@app.route('/login')
def login():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    userinfo = resp.json()
    session["email"] = userinfo["email"]
    # do something with the token and profile
    return redirect('/')

@app.route('/logout')
def logout_user():
    for key in session.keys():
        session.pop(key)
    return redirect('/')



if __name__ == "__main__":
    app.run(    )