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
db_path = 'sqlite:////home/lastc/FxyApi/FxyAPI.db'
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

#############################################################

#Models
class user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

class group(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	code = db.Column(db.String(50))
	name = db.Column(db.String(50))
	owner_id = db.Column(db.Integer)

class post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    content = db.Column(db.String(400))
    author = db.Column(db.String(50))
    topic = db.Column(db.String(50))
    group_id = db.Column(db.String(50))
    
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

#User manipulation
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
def create_user():
	data = request.get_json()
	
	print(user.query.filter_by(name=data['name']).first())
	if user.query.filter_by(name=data['name']).first():
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

#Group manipulation
@app.route('/groups', methods=['POST'])
@token_required
def create_group(current_user):
	data = request.get_json()
	
	if group.query.filter_by(code=data['code']).first():
		return sendMsg('Group code already exists!')
	
	new_group = group(code=str(data['code']), name=data['name'], owner_id=current_user.id)
	db.session.add(new_group)
	db.session.commit()
	
	return sendMsg('Group created successfuly!')

@app.route('/groups/<group_code>', methods=['DELETE'])
@token_required
def delete_group(current_user, group_code):
	
	trg_group = group.query.filter_by(code=group_code).first()
	
	if not trg_group:
		return sendMsg("Group not found!")
	elif trg_group.owner_id != current_user.id:
		return sendMsg("Permission denied!")	
	posts = post.query.filter_by(group_id=trg_group.code)
	for pst in posts:
		db.session.delete(pst)
	db.session.delete(trg_group)
	db.session.commit()
	return sendMsg("Gorup and posts deleted!")

@app.route('/groups', methods=['GET'])
@token_required
def show_groups(current_user):
	groups = group.query.all()
	group_list = []
	for grp in groups:
		gj = {}
		gj['name'] = grp.name
		gj['code'] = grp.code
		group_list.append(gj)
	return sendMsg(group_list, 'Groups')
	
#############################################################

#Post manipulation
@app.route('/posts', methods=['POST'])
@token_required
def create_posts(current_user):
	data = request.get_json()
	
	if post.query.filter_by(title=data['title']).first():
		return sendMsg('Post title already exists!')
	if not group.query.filter_by(code=data['group_id']).first():
		return sendMsg('Group does not exists!')
		
	new_post = post(author=current_user.name, title=data['title'], group_id=data['group_id'], content=data['content'], topic = data['topic'])
	db.session.add(new_post)
	db.session.commit()
	
	return sendMsg('Post created successfuly!')

@app.route('/posts/<group_code>/<name>', methods=['DELETE'])
@token_required
def delete_posts(current_user, group_code, name):
	pst = post.query.filter_by(title=name, group_id=group_code).first()
	if not pst:
		return sendMsg('Post not found!')
	
	if current_user.name == pst.author or current_user.id == pst_group.owner_id:
		db.session.delete(pst)
		db.session.commit()
	else:
		return sendMsg('Access denied!')
	return sendMsg('Post deleted!')	

@app.route('/groups/<group_code>', methods=['GET'])
@token_required
def show_group_posts(current_user, group_code):
	trg_group = group.query.filter_by(code=group_code).first()
	
	if not trg_group:
		return sendMsg("Group not found!")
	
	group_posts = post.query.filter_by(group_id=trg_group.code)
	
	post_list = []
	for pst in group_posts:
		pj = {}
		pj['title'] = pst.title
		pj['content'] = pst.content
		pj['author'] = pst.author
		pj['topic'] = pst.topic
		post_list.append(pj)
	
	return sendMsg(post_list, 'posts')

@app.route('/posts/<group_code>', methods=['GET'])
@token_required
def search_posts(current_user, group_code):
	data = request.get_json()
	try:
		posts = post.query.filter_by(title=data['title'], group_id = group_code)
	except:
		pass
	try:
		posts = post.query.filter_by(author=data['author'], group_id = group_code)
	except:
		pass
	try:
		posts = post.query.filter_by(topic=data['topic'], group_id = group_code)
	except:
		pass
	
	if not posts.first():
		return sendMsg("Post(s) not found!")
		
	post_list = []
	for pst in posts:
		pj = {}
		pj['title'] = pst.title
		pj['content'] = pst.content
		pj['author'] = pst.author
		pj['topic'] = pst.topic
		post_list.append(pj)
	
	return sendMsg(post_list, 'posts')


#@app.route('/posts', methods=['POST'])
#@token_required
#def _post(current_user):

#@app.route('/posts', methods=['POST'])
#@token_required
#def _post(current_user):

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
		token = jwt.encode({'public_id' : usr.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=200)}, app.config['SECRET_KEY'])
		
		return sendMsg(token.decode('UTF-8'), 'token')
	return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic real="Login required!"'})

#############################################################
if __name__ == '__main__':
	app.run(debug=True)
