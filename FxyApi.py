from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

#############################################################

#Application settings
app = Flask(__name__)
token_header = "x-access-token"

#############################################################

#Get API key
key = ' '
with open("../keys/FxyApi.key") as f:
    key = f.readline()
app.config['SECRET_KEY'] = key

#############################################################

#Database configuration
db_path = 'sqlite:///FxyAPI.db'
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#############################################################

#Utils
def usrJson(usr):
	user_data = {}
	user_data['public_id']= usr.public_id
	user_data['name']= usr.name
	user_data['password']= usr.password
	user_data['admin']= usr.admin
	return user_data	

def sendMsg(msg, param = 'msg'):
	return jsonify({param : msg})

#Models
class user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

    posts = db.relationship('post', backref='user', lazy=True)

class post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    content = db.Column(db.String(400))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

#############################################################

#Decorators
def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		
		if token_header in request.headers:
			token = request.headers[token_header]
		if not token:
			return sendMsg('Token missing')
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = user.query.filter_by(public_id = data['public_id']).first()
		except:
			return sendMsg('Token is invalid!'), 401
		
		return f(current_user, *args, **kwargs)
	return decorated

#############################################################

#User database manipulation
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
	if not current_user.admin:
		return sendMsg("Access denied, admin required!")
	usr = user.query.filter_by(public_id = public_id).first()
	if not usr:
		return sendMsg('User not found')
	else:
		return sendMsg(usrJson(usr), 'user')	

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
	if not current_user.admin:
		return sendMsg("Access denied, admin required!")
	users = user.query.all()
	output = []
	for usr in users:
		print(usr)
		user_data = usrJson(usr)
		output.append(user_data)
	return sendMsg(output, 'usr')

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
	data = request.get_json()
	
	if user.query.filter_by(name=data['name']):
		return sendMsg('User already exists!')
	
	hash_passwd = generate_password_hash(data['password'], method='sha256')
	
	new_user = user(public_id=str(uuid.uuid4()), name=data['name'], password=hash_passwd , admin=False)
	db.session.add(new_user)
	db.session.commit()

	return sendMsg('User '+ new_user.name +' created')

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
	if not current_user.admin:
		return sendMsg("Access denied, admin required!")
	
	usr = user.query.filter_by(public_id = public_id).first()
	if not usr:
		return sendMsg('User not found')
	usr.admin = True
	db.session.commit()
	return sendMsg('User have been promoted')

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
	if not current_user.admin:
		return sendMsg("Access denied, admin required!")
	usr = user.query.filter_by(public_id = public_id).first()
	if not usr:
		return sendMsg('User not found')
	db.session.delete(usr)
	db.session.commit()
	return sendMsg('User have been deleted')

#############################################################

#Authentication space
@app.route('/login')
def login():
	auth =request.authorization
	if not auth or not auth.username or not auth.password:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic real="Login required!"'})
	
	usr = user.query.filter_by(name=auth.username).first()
	
	if not usr:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic real="Login required!"'})
	
	if check_password_hash(usr.password, auth.password):
		token = jwt.encode({'public_id' : usr.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
		
		return sendMsg(token.decode('UTF-8'), 'token')
	return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic real="Login required!"'})

#############################################################
if __name__ == '__main__':
	app.run(debug=True)
