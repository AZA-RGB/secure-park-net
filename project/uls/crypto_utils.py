from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.x509 import load_pem_x509_csr
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import base64
import requests
import json,subprocess
from datetime import datetime, timedelta
def issue_certificate(csr, ca_private_key, ca_cert, validity_days=365):
    """
    Issue a certificate using a CSR as a Certificate Authority (CA).

    Args:
        csr (x509.CertificateSigningRequest): CSR to sign.
        ca_private_key: Private key of the CA.
        ca_cert (x509.Certificate): CA certificate.
        validity_days (int): Number of days the certificate is valid for.

    Returns:
        x509.Certificate: Issued certificate.
    """
    subject = csr.subject
    issuer = ca_cert.subject
    serial_number = x509.random_serial_number()
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=validity_days)
    
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    )

    certificate = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    return certificate

def generate_csr_from_key(key_file_path, csr_out_path, country, state, locality, organization, common_name):
    # OpenSSL command to generate a CSR
    openssl_command = f"openssl req -new -key {key_file_path} -out {csr_out_path} -subj \"/C={country}/ST={state}/L={locality}/O={organization}/CN={common_name}\""
    
    # Run the command
    subprocess.run(openssl_command, check=True, shell=True)
    print(f"CSR saved to {csr_out_path}")














def load_cert(certificate_path):
    with open(certificate_path,"rb") as cert_file:
        cert_data = cert_file.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

def verify_certificate(ca_cert,cert_to_verify,CN):
    try:
        ca_cert.public_key().verify(
            cert_to_verify.signature,
            cert_to_verify.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_verify.signature_hash_algorithm
        )
        return cert_to_verify.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value==CN
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def load_private_key(key_file_path):
    with open(key_file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Provide password if the key is encrypted
            backend=default_backend()
        )
    return private_key

def sign_message(message,private_key):
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_digital_signature(message,digital_signature,signer_pubKey):
    try:
        signer_pubKey.verify(
            digital_signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()  # Hash algorithm used in the signature
        )
        return True
    except Exception as e:
        print("Signature is invalid.")
        return False

def sym_encrypt(message, key, iv):
    """
    Encrypts a message using AES CBC mode with the given key and IV.

    :param message: The message to encrypt (string).
    :param key: The AES key (bytes).
    :param iv: The Initialization Vector (bytes).
    :return: Encrypted message (Base64 encoded).
    """
    # Ensure the key and IV are the correct length
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the message to be a multiple of block size (16 bytes for AES)
    padded_message = pad(message.encode(), AES.block_size)
    
    # Encrypt the message
    encrypted_message = cipher.encrypt(padded_message)
    
    # Return the encrypted message as base64 encoded
    return base64.b64encode(encrypted_message).decode()


def sym_decrypt(encrypted_message, key, iv):
    """
    Decrypts a message using AES CBC mode with the given key and IV.

    :param encrypted_message: The encrypted message (Base64 encoded).
    :param key: The AES key (bytes).
    :param iv: The Initialization Vector (bytes).
    :return: Decrypted message (string).
    """
    # Decode the base64 encoded encrypted message
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    
    # Initialize the AES cipher for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the message
    decrypted_message = cipher.decrypt(encrypted_message_bytes)
    
    # Unpad the decrypted message to get the original message
    original_message = unpad(decrypted_message, AES.block_size).decode()
    
    return original_message


def asym_encrypt(message,receiver_pubKey):
    return receiver_pubKey.encrypt(
        message.encode(),
        padding.PKCS1v15(),
    )

def asym_decrypt(cipherText,receiver_privateKey):
    return receiver_privateKey.decrypt(
        cipherText,
        padding.PKCS1v15(),
    ).decode()


def hash_pub_key(cert):

    pubkey_bytes = cert.public_key().public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo
    )
    # Hash the public key using SHA-256
    return hashlib.sha256(pubkey_bytes).hexdigest()
      

def encrypt_fields(fields, receiver_public_key):
    """
    :return: encrypted fields (Base64 encoded) (json serializable)
    """
    encrypted_data=asym_encrypt(json.dumps(fields),receiver_public_key)
    return base64.b64encode(encrypted_data).decode('utf-8')
    


def decrypt_received_data(encrypted_data_base64,receiver_privateKey):

    encrypted_value = base64.b64decode(encrypted_data_base64)
    return asym_decrypt(encrypted_value, receiver_privateKey)




def data_is_secure(encrypted_data,digital_signature,receiver_private_key,sender_pub_key):
    """
    """
    try:
        decrypted_data_str = decrypt_received_data(encrypted_data,receiver_private_key)
        digital_signature=base64.b64decode(digital_signature)
        signature_valid=verify_digital_signature(decrypted_data_str,digital_signature,sender_pub_key)
        if(signature_valid):
            decrypted_data_dict=json.loads(decrypted_data_str)  
            return decrypted_data_dict
    except Exception as e:
        print(e)
        return False
    return False
    

    