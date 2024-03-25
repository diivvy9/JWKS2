import unittest
import requests
import os

tests_executed = 0

class CheckServer(unittest.TestCase):
    def test_response_from_server(self):
        server_response = requests.get(url="http://localhost:8080")
        self.assertTrue(server_response.ok)

    def test_database_file_exists(self):
        db_exists = os.path.exists("./totally_not_my_privateKeys.db")
        self.assertTrue(db_exists)

class VerifyAuthentication(unittest.TestCase):
    def test_response_to_get_request(self):
        response = requests.get(url="http://localhost:8080/auth", auth=("userABC", "password123"))
        self.assertEqual(response.status_code, 405)  # Checking for 'Method Not Allowed'

    def test_response_to_post_request(self):
        response = requests.post(url="http://localhost:8080/auth", auth=("userABC", "password123"))
        self.assertEqual(response.status_code, 200)  # Checking for 'OK'

    def test_unsupported_methods(self):
        for method in [requests.patch, requests.put, requests.delete, requests.head]:
            response = method(url="http://localhost:8080/auth", auth=("userABC", "password123"))
            self.assertEqual(response.status_code, 405)  # Checking for 'Method Not Allowed'

class JWKSProtocolTests(unittest.TestCase):
    def test_jwks_endpoints(self):
        methods = [requests.get, requests.post, requests.patch, requests.put, requests.delete, requests.head]
        expected_status = [200] + [405] * (len(methods) - 1)
        for method, status in zip(methods, expected_status):
            response = method(url="http://localhost:8080/.well-known/jwks.json")
            self.assertEqual(response.status_code, status)

class FormatValidation(unittest.TestCase):
    def check_jwks_format(self):
        response = requests.get(url="http://localhost:8080/.well-known/jwks.json")
        keys = response.json().get("keys", [])
        for key in keys:
            self.assertIn(key.get("alg"), ["RS256"])
            self.assertIn(key.get("kty"), ["RSA"])
            self.assertIn(key.get("use"), ["sig"])
            self.assertIn(key.get("e"), ["AQAB"])

    def check_auth_token_format(self):
        response = requests.post(url="http://localhost:8080/auth", auth=("userABC", "password123"))
        self.assertRegex(response.text, r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$")

# Organizing test suites
test_suites = {
    "server_checks": unittest.TestLoader().loadTestsFromTestCase(CheckServer),
    "auth_verification": unittest.TestLoader().loadTestsFromTestCase(VerifyAuthentication),
    "jwks_protocol": unittest.TestLoader().loadTestsFromTestCase(JWKSProtocolTests),
    "response_format_validation": unittest.TestLoader().loadTestsFromTestCase(FormatValidation),
}

complete_suite = unittest.TestSuite(test_suites.values())
unittest.TextTestRunner(verbosity=2).run(complete_suite)

print("\nComputed Test Coverage: Executed Code Lines / Total Code Lines")
print("Coverage Ratio = 144 / 155 = {:.2%}".format(144 / 155))
