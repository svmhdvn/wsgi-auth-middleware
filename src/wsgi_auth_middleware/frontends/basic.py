import base64


class BasicFrontend:
    def __init__(self, auth_backends, realm="foo"):
        self.auth_backends = auth_backends
        self.realm = realm

    def __call__(self, scheme, data):
        if scheme.lower() != "basic":
            return None

        # TODO: handle error here
        # TODO: figure out typing and naming for "password-based" backends
        username, password = base64.b64decode(data).split(b":", 1)
        return (any(ab(username, password) for ab in self.auth_backends) or None) and username.decode("utf-8")

    def www_authenticate(self):
        return f'Basic realm="{self.realm}"'
