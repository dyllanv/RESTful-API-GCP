from __init__ import app
from boats import boats_bp
from loads import loads_bp
from users import users_bp
from oauth import oauth_bp


app.register_blueprint(oauth_bp)
app.register_blueprint(boats_bp)
app.register_blueprint(loads_bp)
app.register_blueprint(users_bp)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
