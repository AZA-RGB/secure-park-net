from db import db



class User(db.Model):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key=True)
    car_id = db.Column(db.Integer)
    phone_number = db.Column(db.Integer)
    name = db.Column(db.String(100))
    role = db.Column(db.String(100))
    password = db.Column(db.String(200))
    pubkey=db.Column(db.Text,nullable=True)
    api_token=db.Column(db.String(100),nullable=True)
    logs = db.relationship('Log', back_populates='user')