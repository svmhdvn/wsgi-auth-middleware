import pam
import base64

class HTTPBasicPAM():
    def __init__(self, app, pam_service='login', realm='My Website'):
        self.app = app
        self.pam_service = pam_service
        self.realm = realm
        self.pam = pam.PamAuthenticator()

    def __call__(self, environ, start_response):
        def repl_start_response(status, headers, exc_info=None):
            if status.startswith('401'):
                # NOTE we don't want to remove since we want to chain with other middlewares
                #remove_header(headers, 'WWW-Authenticate')
                headers.append(('WWW-Authenticate', f'Basic realm="{self.realm}"'))
            return start_response(status, headers)

        auth = environ.get('HTTP_AUTHORIZATION')
        if not auth: return self.app(environ, repl_start_response)

        scheme, data = auth.split(None, 1)
        if scheme.lower() != 'basic': return self.app(environ, repl_start_response)

        # TODO handle exceptions and errors properly with HTTP codes accordingly
        # TODO handle opening and closing session
        username, password = base64.b64decode(data).split(b':', 1)
        if not pam.authenticate(username, password, service=self.pam_service):
            return self.app(environ, repl_start_response)

        environ['REMOTE_USER'] = username.decode('utf-8')
        del environ['HTTP_AUTHORIZATION']

        return self.app(environ, repl_start_response)

    #def bad_auth(self, environ, start_response):
    #    body = 'Please authenticate'
    #    headers = [
    #        ('content-type', 'text/plain'),
    #        ('content-length', str(len(body))),
    #        ('WWW-Authenticate', f'Basic realm="{self.realm}"'),
    #    ]
    #    start_response('401 Unauthorized', headers)
    #    return [body]

#def remove_header(headers, name):
#    for header in headers:
#        if header[0].lower() == name.lower():
#            headers.remove(header)
#            break
