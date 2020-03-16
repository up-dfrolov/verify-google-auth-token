from flask import Flask, jsonify, request

from google.oauth2 import id_token
from google.auth.transport import requests

from config import GOOGLE_AUTH_CLIENT_ID


app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'


@app.route('/check_token', methods=['POST'])
def check_token():
    token = request.data
    idinfo = None
    try:
        # Specify the CLIENT_ID of the app that accesses the backend:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_AUTH_CLIENT_ID)

        # Or, if multiple clients access the backend server:
        # idinfo = id_token.verify_oauth2_token(token, requests.Request())
        # if idinfo['aud'] not in [CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]:
        #     raise ValueError('Could not verify audience.')

        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        # If auth request is from a G Suite domain:
        # if idinfo['hd'] != GSUITE_DOMAIN_NAME:
        #     raise ValueError('Wrong hosted domain.')

        # ID token is valid. Get the user's Google Account ID from the decoded token.
        userid = idinfo['sub']
    except ValueError as e:
        # Invalid token
        return jsonify({'errorMsg': f'{e}'}), 401

    return jsonify(idinfo)


if __name__ == '__main__':
    app.run(debug=True)
