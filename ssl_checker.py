import ssl
import socket
import sys
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import idna

if len(sys.argv) < 2:
    print("Usage: python ssl_checker.py <site_name>")
    sys.exit(1)

SITE_NAME = sys.argv[1]


def check_ssl_details(hostname):
    context = ssl.create_default_context()
    try:
        hostname_idna = idna.encode(hostname).decode("ascii")
        with socket.create_connection((hostname_idna, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname_idna) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                serial_number = hex(cert.serial_number)
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                days_to_expiry = (not_after - datetime.utcnow()).days

                sha256_fingerprint = cert.fingerprint(hashes.SHA256())
                sha1_fingerprint = cert.fingerprint(hashes.SHA1())

                sha256_fingerprint_hex = ":".join([
                    "{:02X}".format(b) for b in sha256_fingerprint
                ])
                sha1_fingerprint_hex = ":".join([
                    "{:02X}".format(b) for b in sha1_fingerprint
                ])

                print(f"\nCertificate details for {hostname}:")
                print(f"Issued To: {subject}")
                print(f"Issued By: {issuer}")
                print(f"Serial Number: {serial_number}")
                print(f"Valid From: {not_before}")
                print(f"Valid Until: {not_after}")
                print(f"Days Until Expiry: {days_to_expiry}")
                print(f"SHA256 Fingerprint: {sha256_fingerprint_hex}")
                print(f"SHA1 Fingerprint: {sha1_fingerprint_hex}")

                print("\nCertificate Extensions:")
                for ext in cert.extensions:
                    ext_name = ext.oid._name or ext.oid.dotted_string
                    print(f"- {ext_name}: {ext.value}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    check_ssl_details(SITE_NAME)
