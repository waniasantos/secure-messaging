import os
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Crypto:
    @staticmethod
    def generate_ecdhe_keypair():
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()
    
    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    @staticmethod
    def deserialize_public_key(key_bytes):
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), key_bytes
        )
    
    @staticmethod
    def compute_shared_secret(my_private_key, their_public_key):
        return my_private_key.exchange(ec.ECDH(), their_public_key)
    
    
    @staticmethod
    def hkdf_extract(salt, input_key_material):
        return hmac.new(salt, input_key_material, hashlib.sha256).digest()
    
    @staticmethod
    def hkdf_expand(pseudo_random_key, info, length):
        output_key_material = b""
        previous_block = b""
        counter = 1
        
        while len(output_key_material) < length:
            previous_block = hmac.new(
                pseudo_random_key,
                previous_block + info.encode() + bytes([counter]),
                hashlib.sha256
            ).digest()
            output_key_material += previous_block
            counter += 1
        
        return output_key_material[:length]
    
    @staticmethod
    def derive_tls13_keys(shared_secret, salt):
        prk = Crypto.hkdf_extract(salt, shared_secret)
        
        key_c2s = Crypto.hkdf_expand(prk, "c2s", 16)
        key_s2c = Crypto.hkdf_expand(prk, "s2c", 16)
        
        return key_c2s, key_s2c
    
    
    @staticmethod
    def encrypt_aes_gcm(key, nonce, plaintext, associated_data):
        aesgcm = AESGCM(key)
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        return aesgcm.encrypt(nonce, plaintext, associated_data)
    
    @staticmethod
    def decrypt_aes_gcm(key, nonce, ciphertext, associated_data):
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    
    @staticmethod
    def sign_rsa(private_key, data):
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    @staticmethod
    def verify_rsa(public_key, signature, data):
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False