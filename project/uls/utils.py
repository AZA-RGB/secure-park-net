import subprocess
import tempfile



def verify_certificate(ca_cert_path, cert_data):
    # Save the received certificate data to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as temp_cert_file:
        temp_cert_file.write(cert_data.encode('utf-8'))  # Assuming cert_data is a string
        temp_cert_path = temp_cert_file.name

    # OpenSSL command to verify if the certificate is signed by the CA
    openssl_command = f"openssl verify -CAfile {ca_cert_path} {temp_cert_path}"
    
    # Run the command and capture the output
    result = subprocess.run(openssl_command, shell=True, capture_output=True, text=True)
    
    # Check the result and print the output
    if result.returncode == 0:
        print(f"Certificate is valid and signed by the CA.")
        return True
    else:
        print(f"Verification failed: {result.stderr.strip()}")
        return False


def send_client_cert(client_cert_path):

    try:
        files = {'certificate': ('clientCertificate.crt', client_cert.public_bytes(serialization.Encoding.PEM), 'application/x-pem-file')}
        response = requests.post('http://127.0.0.1:3000/upload_certificate', files=files)
        response.raise_for_status()  # Raise an error for HTTP status codes 4xx or 5xx
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending ATM certificate: {e}")
        return False


# # CSR generation test
key_file_path = '../server/server_private_key.pem'
country = "SY"
state = "Damascus"
locality = "Sahnaya"
organization = "parking org"
common_name = "parking server"
csr_out_path="../server/server_CSR.csr"
csr = generate_csr_from_key(key_file_path,csr_out_path, country, state, locality, organization, common_name)
print(csr)

# # private key generation test
# private_key = generate_private_key(key_out_path="client/client_private_key.pem")



# # certificate issuance test
# csr_path='csr_test.csr'
# ca_cert_path='CA_self_signed_certificate.crt'
# ca_key_path='CA_private_key.pem'
# output_cert_path='certificate_test.crt'

# sign_csr_as_ca(csr_path, ca_cert_path, ca_key_path, output_cert_path)

# # verify a certificate is signed by a CA TODO:pass the certificate as data insteadd of a file path
# ca_cert_path='CA_self_signed_certificate.crt'
# cert_path='certificate_test.crt'
# verify_certificate(ca_cert_path, cert_path)


