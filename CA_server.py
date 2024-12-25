from flask import Flask, request, jsonify,Response
from crypto_utils import load_private_key,load_cert, issue_certificate
from cryptography.x509 import load_pem_x509_csr
from cryptography.hazmat.primitives.serialization import Encoding

import os

app = Flask(__name__)

# # Load the CA's private key and certificate
# CA_KEY_FILE = 'ca_private_key.pem'
# CA_CERT_FILE = 'ca_certificate.pem'

# with open(CA_KEY_FILE, 'rb') as key_file:
#     ca_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())

# with open(CA_CERT_FILE, 'rb') as cert_file:
#     ca_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())

ca_private_key=load_private_key('CA_private_key.pem')
ca_cert=load_cert('CA_self_signed_certificate.crt')

@app.route('/sign_csr', methods=['POST'])
def sign_csr():
    # Get the CSR from the request
    csr_data = request.files['csr']
    if not csr_data:
        return jsonify({"error": "No CSR provided"}), 400

    try:
        # Load the CSR
        csr=load_pem_x509_csr(csr_data.read())
        # print(csr)
        client_cert=issue_certificate(csr,ca_private_key=ca_private_key,ca_cert=ca_cert,validity_days=3650)
        
        pem_cert=client_cert.public_bytes(encoding=Encoding.PEM)
        
        response = Response(pem_cert, mimetype="application/x-pem-file")
        return response

    except Exception as e:
        return jsonify({"error": "Failed to process CSR", "details": str(e)}), 500


if __name__ == '__main__':
    app.run(port=5001,debug=True)