# SPDX-FileCopyrightText: 2024-present Siva Mahadevan <me@svmhdvn.name>
#
#: SPDX-License-Identifier: MIT

class HttpAuthWsgiMiddleware:
    def __init__(self, app, auth_frontends):
        self.app = app
        self.auth_frontends = auth_frontends

    def __call__(self, environ, start_response):
        def repl_start_response(status, headers, exc_info=None):
            if status.startswith('401'):
                # TODO implement this
                #remove_header(headers, 'WWW-Authenticate')
                for af in self.auth_frontends:
                    headers.append(('WWW-Authenticate', af.www_authenticate()))
            return start_response(status, headers)

        auth = environ.get('HTTP_AUTHORIZATION')
        if auth:
            # TODO handle error here
            scheme, data = auth.split(None, 1)
            for af in self.auth_frontends:
                user = af(scheme, data)
                if user is not None:
                    environ['REMOTE_USER'] = user
                    del environ['HTTP_AUTHORIZATION']
                    break

        return self.app(environ, repl_start_response)
