from flask import Flask
from google.cloud import datastore
import secrets
client = datastore.Client()

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)
