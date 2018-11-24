from FxyApi import *

db.create_all()
db.session.commit()
hash_passwd = generate_password_hash('1234', method='sha256')
new_user = user(public_id=str(uuid.uuid4()), name='admin', password=hash_passwd , admin=True)

db.session.add(new_user)
db.session.commit()
