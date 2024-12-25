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
def get_ca_cert():
    """
    return:  x509 certificate object
    """
    try:
        response = requests.get('http://localhost:5001/get-ca-certificate')
        response.raise_for_status()
        ca_certificate_pem = response.content
        print(ca_certificate_pem)
        return load_pem_x509_certificate(ca_certificate_pem, default_backend())
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving ca certificate: {e}")
    except ValueError as e:
        print(f"Error loading ca certificate: {e}")
    return None

if __name__== "__main__":
    app=create_app()
    app.run(debug=True)
