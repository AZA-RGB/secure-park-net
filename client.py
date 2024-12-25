import requests
from crypto_utils import load_private_key,load_cert, issue_certificate
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



# # gettign cetrificate from a CA 
# csr_file = "csr_test.csr"
# CA_issue_url = "http://localhost:5001/sign_csr"
# get_cert_from_csr(csr_file,CA_issue_url)
get_ca_cert()


