import contextlib

with contextlib.suppress(ImportError):
    from wsgi_auth_middleware.backends.pam import PamBackend as PamBackend

with contextlib.suppress(ImportError):
    from wsgi_auth_middleware.backends.gssapi import GssapiBackend as GssapiBackend
