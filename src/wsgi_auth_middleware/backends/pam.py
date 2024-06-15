import pam

class PamBackend:
    def __init__(self, service='login'):
        self.service = service
        self.pam = pam.PamAuthenticator()

    def __call__(self, username, password):
        return pam.authenticate(username, password, service=self.service)
