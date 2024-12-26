import sys
import os
sys.path.append(os.path.abspath('/home/elyas/Music/IdeaProjects/ParkSecureNet/project/uls'))

import requests
from crypto_utils import load_private_key,load_cert, issue_certificate,verify_certificate,generate_csr_from_key
from cryptography.x509 import load_pem_x509_csr,load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding


def get_cert_from_csr(csr_file_path,CA_issue_url):
    # Send the CSR to the server
    with open(csr_file_path, 'rb') as csr:
        response = requests.post(CA_issue_url, files={"csr": csr})

    # Handle the server's response
    if response.status_code == 200:
        print("Signed certificate received:")
        print(response.text)

        # Save the signed certificate to a file
        with open("my_certificate.pem", "wb") as f:
            f.write(response.content)
    else:
        print(f"Failed to get a certificate: {response.status_code}")
        print(response.json())



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



def get_server_cert():
    """
    return: the server's x509 certificate object
    """
    try:
        response = requests.get('http://localhost:3000/get-server-certificate')
        response.raise_for_status()
        ca_certificate_pem = response.content
        print(ca_certificate_pem)
        return load_pem_x509_certificate(ca_certificate_pem, default_backend())
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving ca certificate: {e}")
    except ValueError as e:
        print(f"Error loading ca certificate: {e}")
    return None

# upload client certificate to the parking server
def send_client_cert(client_cert):
    try:
        files = {'certificate': ('clientCertificate.crt', client_cert.public_bytes(Encoding.PEM), 'application/x-pem-file')}
        response = requests.post('http://127.0.0.1:3000/upload_certificate', files=files)
        print(response.json())
        response.raise_for_status()  # Raise an error for HTTP status codes 4xx or 5xx
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending client's certificate: {e}")
        return False


# # gettign cetrificate from a CA 
# csr_file = "csr_test.csr"
# CA_issue_url = "http://localhost:5001/sign_csr"
# get_cert_from_csr(csr_file,CA_issue_url)

# key_file_path = 'client_private_key.pem'
# country = "SY"
# state = "Damascus"
# locality = "jaramana"
# organization = "parkingclient org"
# common_name = "parking client"
# csr_out_path="client_CSR.csr"
# csr = generate_csr_from_key(key_file_path,csr_out_path, country, state, locality, organization, common_name)
# ca_cert=get_ca_cert()
# get_cert_from_csr('client_CSR.csr','http://localhost:5001/sign_csr')

client_cert=load_cert('my_certificate.pem')
send_client_cert(client_cert)
# server_cert=get_server_cert()
# ca_cert=get_ca_cert()
# print(verify_certificate(ca_cert,server_cert,'parking server'))


