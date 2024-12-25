import requests

# Flask CA server endpoint


# File path to the CSR

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






# # gettign cetrificate from a CA 
# csr_file = "csr_test.csr"
# CA_issue_url = "http://localhost:5001/sign_csr"
# get_cert_from_csr(csr_file,CA_issue_url)



