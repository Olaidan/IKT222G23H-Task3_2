import pyotp
from flask import Flask, request, redirect, session, url_for, render_template_string
import os
import urllib.parse
from flask_oauthlib.client import OAuth
import qrcode

app = Flask(__name__)
app.secret_key = os.urandom(24)

REDIRECT_URI = "http://127.0.0.1:5000/callback"

oauth = OAuth(app)
auth0 = oauth.remote_app(
    'auth0',
    consumer_key='',
    consumer_secret='',
    request_token_params={
        'scope': 'openid profile email',
        'audience': 'https://ikt222grp10.eu.auth0.com/userinfo'
    },
    base_url='https://ikt222grp10.eu.auth0.com',
    access_token_method='POST',
    access_token_url='/oauth/token',
    authorize_url='/authorize',
)

@auth0.tokengetter
def get_auth0_oauth_token():
    return session.get('access_token')


@app.route("/login")
def login():
    return auth0.authorize(callback=url_for('auth0_callback', _external=True))


@app.route("/callback")
def auth0_callback():
    resp = auth0.authorized_response()

    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['access_token'] = resp['access_token']
    user_info = auth0.get('userinfo')
    session['profile'] = user_info.data
    return redirect('/otp')


@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'profile' not in session:
        return redirect('/login')

    user_email = session['profile']['email']

    if 'otp_secret' not in session:
        session['otp_secret'] = pyotp.random_base32()

    totp = pyotp.TOTP(session['otp_secret'])

    if request.method == 'GET':
        otp_uri = totp.provisioning_uri(user_email, issuer_name="IKT222GRP10")
        otp_uri_encoded = urllib.parse.quote(otp_uri)

        # QR generator
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img_path = os.path.join(os.getcwd(), 'static', 'otp_qr.png')
        img.save(img_path)

        return render_template_string('''
        <img src="{{ url_for('static', filename='otp_qr.png') }}" alt="OTP QR Code">
        <form method="post">
            <input type="text" name="token" placeholder="Enter your token">
            <button type="submit">Verify</button>
        </form>
        <br>
        <a href="/show_token">Show Access Token</a>
        ''')

    elif request.method == 'POST':
        token = request.form.get('token')
        if totp.verify(token):
            return 'Token is now registered. <a href="/show_token">Show Access Token</a>'
        else:
            return 'Token is invalid.'

@app.route('/show_token')
def show_token():
    if 'access_token' not in session:
        return "No access token found. Please login.", 401

    token = session['access_token']

    return render_template_string('''
    <h3>Access Token:</h3>
    <p>{{ token }}</p>
    <br>
    ''', token=token)
