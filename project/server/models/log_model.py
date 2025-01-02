from db import db


class Log(db.Model):
    __tablename__='logs'
    id = db.Column(db.Integer, primary_key=True)
    operation = db.Column(db.Integer)
    digital_signature = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='logs')
