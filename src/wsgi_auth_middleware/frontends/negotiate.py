import base64


class NegotiateFrontend:
    def __init__(self, auth_backends):
        self.auth_backends = auth_backends

    def __call__(self, scheme, data):
        if scheme.lower() != "negotiate":
            return None

        try:
            client_token = base64.b64decode(data, validate=True)
        except Exception:
            # self.logger.exception("Could not base64 decode the client token")
            return None

        for ab in self.auth_backends:
            user = ab(client_token)
            if user is not None:
                return user
        return None

    # TODO: think about supporting mutual authentication
    def www_authenticate(self):
        return "Negotiate"
