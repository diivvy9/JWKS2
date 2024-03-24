# Name: Divya Darji
# UNT ID: 11511565 
#eeuid: ddd0239
#Project 2 JWKS

# Necessary library imports
from http.server import HTTPServer, BaseHTTPRequestHandler
import sqlite3
import json
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime, timedelta, timezone
from jwt.utils import base64url_encode, bytes_from_int
from calendar import timegm

# Class to handle HTTP requests
class HTTPRequestHandler(BaseHTTPRequestHandler):
    KeyStorage = {"keys": []}  # JSON Web Key storage

    # Unsupported HTTP methods
    def unsupported_method(self):
        self.send_response(405)
        self.end_headers()

    do_PUT = do_DELETE = do_PATCH = do_HEAD = unsupported_method

    def do_GET(self):
        # Return JWKS for valid keys
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.end_headers()
            cursor = db.cursor()

            query = "SELECT * FROM keys WHERE exp > ?;"
            cursor.execute(query, (timegm(datetime.now(timezone.utc).timetuple()),))
            rows = cursor.fetchall()

            for row in rows:
                priv_key = load_pem_private_key(row[1], password=None)
                pub_key = priv_key.public_key()

                jwk = {
                    "kid": str(row[0]),
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "n": base64url_encode(bytes_from_int(pub_key.public_numbers().n)).decode("utf-8"),
                    "e": base64url_encode(bytes_from_int(pub_key.public_numbers().e)).decode("utf-8"),
                }

                self.KeyStorage["keys"].append(jwk)

            self.wfile.write(json.dumps(self.KeyStorage, indent=1).encode())
        else:
            self.unsupported_method()

    def do_POST(self):
        # Issue JWT based on key validity
        if self.path.startswith("/auth"):
            self.send_response(200)
            self.end_headers()
            cursor = db.cursor()

            expired = "expired=true" in self.path
            query = "SELECT kid, key, exp FROM keys WHERE exp <= ?;" if expired else "SELECT * FROM keys WHERE exp > ?;"
            cursor.execute(query, (timegm(datetime.now(timezone.utc).timetuple()),))
            key_row = cursor.fetchone()

            jwt_payload = jwt.encode(
                {"exp": key_row[2]},
                key_row[1],
                algorithm="RS256",
                headers={"kid": str(key_row[0])}
            )

            self.wfile.write(jwt_payload.encode())
        else:
            self.unsupported_method()

# Initialize and run the server
server_address = ("", 8080)
http_server = HTTPServer(server_address, HTTPRequestHandler)

# Database connection and setup
db = sqlite3.connect("totally_not_my_privateKeys.db")
db.execute(
    """CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);"""
)

# Generate and store RSA keys
print("Setting up RSA keys...")
for _ in range(5):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_bytes = key.private_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization.NoEncryption())

    expiration_time = datetime.now(timezone.utc) + timedelta(hours=-1 if _ % 2 == 0 else 1)
    db.execute("INSERT INTO keys (key, exp) VALUES(?, ?);", (key_bytes, timegm(expiration_time.timetuple())))
db.commit()
print("Server is active on port 8080...")

# Run server indefinitely until interrupted
try:
    http_server.serve_forever()
except KeyboardInterrupt:
    db.close()

# Cleanly shut down the server
http_server.server_close()
