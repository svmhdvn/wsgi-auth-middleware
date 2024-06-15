# Acknowledgements:
# * Testing code forked from https://github.com/deshaw/wsgi-kerberos
#   licensed under BSD-3-Clause. See
#   https://github.com/deshaw/wsgi-kerberos/blob/master/LICENSE
#   for more details.

import copy
import os

import gssapi
import k5test
import requests
import requests_gssapi
from wsgi_intercept import add_wsgi_intercept, remove_wsgi_intercept, requests_intercept

from wsgi_auth_middleware import HttpAuthWsgiMiddleware
from wsgi_auth_middleware.backends import GssapiBackend
from wsgi_auth_middleware.frontends import NegotiateFrontend

REALM = "EXAMPLE.ORG"
HOSTNAME = REALM.lower()
TEST_PORT = 8888
TEST_URL = f"http://{HOSTNAME}:{TEST_PORT}/"
USER1 = (f"user1@{REALM}", "pass1")
USER2 = (f"user2@{REALM}", "pass2")
HTTP_SERVICE = f"HTTP/{HOSTNAME}@{REALM}"


def auth_not_required_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    response_body = f"Hello {environ.get('REMOTE_USER', 'ANONYMOUS')}"
    return [response_body.encode("utf-8")]


def auth_mandatory_app(environ, start_response):
    user = environ.get("REMOTE_USER")
    if user:
        start_response("200 OK", [("Content-Type", "text/plain")])
        response_body = f"Hello {user}"
    else:
        start_response("401 Unauthorized", [("Content-Type", "text/plain")])
        response_body = "Please authenticate"

    return [response_body.encode("utf-8")]


class CustomSpnegoAuth(requests_gssapi.HTTPSPNEGOAuth):
    def __init__(self, creds=None):
        super().__init__(
            target_name=gssapi.Name(HTTP_SERVICE).canonicalize(gssapi.MechType.kerberos),
            creds=creds,
            opportunistic_auth=True,
        )


class BasicAppTestCase(k5test.KerberosTestCase):
    @classmethod
    def _init_env(cls):
        cls._saved_env = copy.deepcopy(os.environ)
        for k, v in cls.realm.env.items():
            os.environ[k] = v

    @classmethod
    def _restore_env(cls):
        for k in copy.deepcopy(os.environ):
            if k in cls._saved_env:
                os.environ[k] = cls._saved_env[k]
            else:
                del os.environ[k]

        cls._saved_env = None

    @classmethod
    def setUpClass(cls):
        cls.realm = k5test.realm.K5Realm(
            realm=REALM,
            create_user=False,
            get_creds=False,
            create_host=False,
        )
        cls.realm.addprinc(USER1[0], USER1[1])
        cls.realm.addprinc(USER2[0], USER2[1])
        cls.realm.addprinc(HTTP_SERVICE)
        # TODO: add test for the absence of the HTTP service principal in the realm
        cls.realm.extract_keytab(HTTP_SERVICE, cls.realm.keytab)
        requests_intercept.install()

        cls._init_env()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        requests_intercept.uninstall()

        cls._restore_env()

    def test_auth_missing_but_not_required(self):
        app = HttpAuthWsgiMiddleware(auth_not_required_app, [NegotiateFrontend([GssapiBackend(HOSTNAME)])])
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL)
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert "WWW-Authenticate" not in r.headers

    def test_auth_invalid_but_not_required(self):
        """
        Ensure that when a user's auth_required_callback returns False,
        and the request includes an invalid auth token,
        the invalid auth is ignored and the request
        is allowed through to the app.
        """
        app = HttpAuthWsgiMiddleware(auth_not_required_app, [NegotiateFrontend([GssapiBackend(HOSTNAME)])])
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, headers={"Authorization": "Negotiate BADTOKEN"})
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert "WWW-Authenticate" not in r.headers

    def test_authentication_valid_but_not_required(self):
        self.realm.kinit(USER1[0], USER1[1])
        user1_creds = gssapi.Credentials.acquire(
            name=gssapi.Name(USER1[0]).canonicalize(gssapi.MechType.kerberos),
            usage="initiate",
        )

        app = HttpAuthWsgiMiddleware(auth_not_required_app, [NegotiateFrontend([GssapiBackend(HOSTNAME)])])
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, auth=CustomSpnegoAuth(user1_creds.creds))
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == f"Hello {USER1[0]}".encode()

    def test_unauthorized(self):
        """
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication.
        """
        app = HttpAuthWsgiMiddleware(auth_mandatory_app, [NegotiateFrontend([GssapiBackend(HOSTNAME)])])
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL)
        remove_wsgi_intercept()

        assert r.status_code == 401
        assert r.content == b"Please authenticate"
        assert r.headers["WWW-Authenticate"] == "Negotiate"
        assert r.headers["Content-Type"] == "text/plain"

    def test_unauthorized_when_missing_negotiate(self):
        """
        Ensure that when the client sends an Authorization header that does
        not start with "Negotiate ", they receive a 401 Unauthorized response
        with a "WWW-Authenticate: Negotiate" header.
        """
        app = HttpAuthWsgiMiddleware(auth_mandatory_app, [NegotiateFrontend([GssapiBackend(HOSTNAME)])])
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, headers={"Authorization": "Basic BADTOKEN"})
        remove_wsgi_intercept()

        assert r.status_code == 401
        assert r.content == b"Please authenticate"
        assert r.headers["WWW-Authenticate"].lower() == "negotiate"
        assert r.headers["Content-Type"] == "text/plain"

    def test_authorized(self):
        """
        Ensure that when the client sends a correct authorization token,
        they receive a 200 OK response and the user principal is extracted and
        passed on to the routed method.
        """
        self.realm.kinit(USER1[0], USER1[1])
        user1_creds = gssapi.Credentials.acquire(
            name=gssapi.Name(USER1[0]).canonicalize(gssapi.MechType.kerberos),
            usage="initiate",
        )

        app = HttpAuthWsgiMiddleware(auth_mandatory_app, [NegotiateFrontend([GssapiBackend(HOSTNAME)])])
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, auth=CustomSpnegoAuth(user1_creds.creds))
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == f"Hello {USER1[0]}".encode()
