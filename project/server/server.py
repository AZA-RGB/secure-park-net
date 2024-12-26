import sys ,os
sys.path.append(os.path.abspath('/home/elyas/Music/IdeaProjects/ParkSecureNet/project/uls'))

from crypto_utils import load_cert,generate_csr_from_key,verify_certificate
from cryptography.x509 import load_pem_x509_csr,load_pem_x509_certificate,NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from flask import Flask,Response,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import requests


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



    key_file_path = 'server_private_key.pem'
    country = "SY"
    state = "Damascus"
    locality = "Sahnaya"
    organization = "parking org"
    common_name = "parking server"
    csr_out_path="server_CSR.csr"
    csr = generate_csr_from_key(key_file_path,csr_out_path, country, state, locality, organization, common_name)
    ca_cert=get_ca_cert()
    get_cert_from_csr('server_CSR.csr','http://localhost:5001/sign_csr')
    server_cert=load_cert('server_certificate.pem')


    @app.route('/get-server-certificate',methods=["GET"])
    def get_server_certificate():
        ser_cert_data=server_cert.public_bytes(Encoding.PEM)
        return Response(
                ser_cert_data,
                mimetype='application/x-pem-file',
                headers={
                    'Content-Disposition': 'attachment; filename="serverCertificate.pem"'
                }
            )

    @app.route('/upload_certificate', methods=['POST'])
    def upload_certificate():
        # Check if a certificate file is part of the request
        if 'certificate' not in request.files:
            return jsonify({"error": "No certificate file provided"}), 400
        
        certificate_file = request.files['certificate']
        
        # Read the contents of the certificate file
        certificate_data = certificate_file.read()
        client_certificate=load_pem_x509_certificate(certificate_data, default_backend())
        
        # now you have the certificate verify the certifiacate then store its public key with the hash 
        if( verify_certificate(ca_cert,client_certificate,CN="parking client")):
            print("from upload certificate")
            print(client_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
            # # store the (PubKeyhash, pubKey)
            # store_pubKey(client_certificate)
            return jsonify({
                "message": "Certificate uploaded successfully",
                "certificate": "certificat valid" # Return the certificate as a string for demonstration
            }),200
        
        return jsonify({
            "message": "Unauthorized",
            "certificate": "certificat not valid" # Return the certificate as a string for demonstration
        }),401





    return app
##############################################################################################





def get_cert_from_csr(csr_file_path,CA_issue_url):
    # Send the CSR to the server
    with open(csr_file_path, 'rb') as csr:
        response = requests.post(CA_issue_url, files={"csr": csr})

    # Handle the server's response
    if response.status_code == 200:
        print("Signed certificate received:")
        # print(response.text)

        # Save the signed certificate to a file
        with open("server_certificate.pem", "wb") as f:
            f.write(response.content)
    else:
        print(f"Failed to get a certificate: {response.status_code}")
        # print(response.json())

def get_ca_cert():
    """
    return:  x509 certificate object
    """
    try:
        response = requests.get('http://localhost:5001/get-ca-certificate')
        response.raise_for_status()
        ca_certificate_pem = response.content
        print('ca certificate')
        print(ca_certificate_pem)
        return load_pem_x509_certificate(ca_certificate_pem, default_backend())
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving ca certificate: {e}")
    except ValueError as e:
        print(f"Error loading ca certificate: {e}")
    return None

if __name__== "__main__":
    app=create_app()
    app.run(debug=True,port=3000)
