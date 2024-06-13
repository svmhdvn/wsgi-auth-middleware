#!/usr/bin/env python3

from wsgiref.util import setup_testing_defaults
from wsgiref.simple_server import make_server
from wsgi_auth_pam import HTTPBasicPAM

# A relatively simple WSGI application. It's going to print out the
# environment dictionary after being updated by setup_testing_defaults
def simple_app(environ, start_response):
    setup_testing_defaults(environ)

    status = '200 OK' if environ.get('REMOTE_USER') else '401 Unauthorized'
    headers = [('Content-type', 'text/plain; charset=utf-8')]

    start_response(status, headers)

    ret = [("%s: %s\n" % (key, value)).encode("utf-8")
           for key, value in environ.items()]
    return ret

with make_server('', 8000, HTTPBasicPAM(simple_app, pam_service='login')) as httpd:
    print("Serving on port 8000...")
    httpd.serve_forever()
