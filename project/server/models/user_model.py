from server import db



class User(db.Model):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    car_id = db.Column(db.Integer)
    phone_number = db.Column(db.Integer)
    name = db.Column(db.String(100))
    role = db.Column(db.String(100))
    password = db.Column(db.String(200))
    logs = db.relationship('Log', back_populates='user')