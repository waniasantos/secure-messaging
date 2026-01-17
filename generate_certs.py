from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime


def generate_self_signed_certificate():    
    print("[CRYPTO] Gerando chave privada RSA-2048...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ceará"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Quixadá"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UFC Campus Quixadá"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Servidor Mensageria Segura"),
    ])
    
    print("[CERTIFICADO] Gerando certificado X.509...")
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    with open("server.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("[OK] Chave privada salva: server.key")
    
    with open("server.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("[OK] Certificado salvo: server.crt")
    
    print("\n[SEGURANCA] Certificado RSA autoassinado gerado com sucesso!")
    print("Validade: 365 dias")
    print("Algoritmo: RSA-2048 + SHA-256\n")


if __name__ == "__main__":
    generate_self_signed_certificate()