# wsgi-auth-middleware

`wsgi-auth-middleware` provides WSGI middleware to perform HTTP authentication (RFC7235) using a variety of schemes.

[![PyPI - Version](https://img.shields.io/pypi/v/wsgi-auth-middleware.svg)](https://pypi.org/project/wsgi-auth-middleware)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/wsgi-auth-middleware.svg)](https://pypi.org/project/wsgi-auth-middleware)

-----

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Supported Specifications](#supported-specifications)
- [License](#license)

## Installation

Each backend requires additional dependencies that must be explicitly chosen using the [PEP508 Extras](https://peps.python.org/pep-0508/#extras) that cover it. The following command will install `wsgi-auth-middleware` with all supported backends.

```console
pip install wsgi-auth-middleware[gssapi,pam]
```

## Usage

This middleware package provides the `HttpAuthWsgiMiddleware` class and various callables that implement authentication primitives. The result of wrapping a WSGI app with `HttpAuthWsgiMiddleware` will be a new WSGI app that performs HTTP authentication and, upon success, places the authenticated username string in `environ["REMOTE_USER"]`.

`wsgi-auth-middleware` is designed to be flexible. You can mix and match HTTP authentication schemes (frontends) with any system authentication backends that support their interfaces. Typical usage looks like this:

```python
from wsgi_auth_middleware import HttpAuthWsgiMiddleware
from wsgi_auth_middleware.frontends import BasicFrontend, NegotiateFrontend
from wsgi_auth_middleware.backends import PamBackend, GssapiBackend

pam_backend = PamBackend(service='my_pam_service')
basic_frontend = BasicFrontend(auth_backends=[pam_backend], realm='my realm')

gssapi_backend = GssapiBackend(fqdn='example.org')
negotiate_frontend = NegotiateFrontend(auth_backends=[gssapi_backend])

# Authentication will be tried in the sequential order given by `auth_frontends`.
authenticated_app = HttpAuthWsgiMiddleware(
    app=my_wsgi_app,
    auth_frontends=[negotiate_frontend, basic_frontend]
)
```

## Supported Specifications

### Currently supported HTTP authentication schemes

* [RFC7235 - Hypertext Transfer Protocol (HTTP/1.1): Authentication](https://datatracker.ietf.org/doc/html/rfc7235)
* [RFC7617 - The 'Basic' HTTP Authentication Scheme](https://datatracker.ietf.org/doc/html/rfc7617)
* [(Kerberos only) RFC4559 - SPNEGO-based Kerberos and NTLM HTTP Authentication in Microsoft Windows](https://datatracker.ietf.org/doc/html/rfc4559)

### WSGI specifications

* [PEP 3333 – Python Web Server Gateway Interface v1.0.1](https://peps.python.org/pep-3333/)
* [A very basic description of authentication opportunities in WSGI](https://wsgi.readthedocs.io/en/latest/specifications/simple_authentication.html)

## License

`wsgi-auth-middleware` is distributed under the terms of the [ISC](https://spdx.org/licenses/ISC.html) license.
