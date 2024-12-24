from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate



db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)

    # Replace these values with your actual MySQL credentials
    USERNAME = 'root'
    PASSWORD = 'yourpassword'
    HOST = 'localhost'
    DATABASE = 'park_secure_net' 

    # SQLAlchemy database URI
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root@{HOST}/{DATABASE}'
    db.init_app(app)
    migrate.init_app(app, db)


    with app.app_context():
        try:
            db.engine.connect()
            print("Database connection successful.")
        except Exception as e:
            print(f"Database connection failed: {e}")
        from models.log_model import Log
        from models.user_model import User
        db.create_all() 
    return app

if __name__== "__main__":
    app=create_app()
    app.run(debug=True)
