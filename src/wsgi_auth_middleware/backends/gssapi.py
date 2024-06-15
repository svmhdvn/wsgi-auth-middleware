import socket

import gssapi


# NOTE only Kerberos-based GSSAPI is supported for now
class GssapiBackend:
    def __init__(self, fqdn=None):
        self.service = gssapi.Name(f"HTTP/{fqdn or socket.getfqdn()}@").canonicalize(gssapi.MechType.kerberos)

    def __call__(self, client_token):
        # TODO: re-acquire credentials only when the credentials expire instead of every request
        try:
            gssapi_creds = gssapi.Credentials(usage="accept", name=self.service)
        except Exception:
            # self.logger.exception("GSSAPI error: Failed to obtain kerberos credentials from the system keytab!")
            return None

        try:
            gssapi_ctx = gssapi.SecurityContext(creds=gssapi_creds, usage="accept")
        except Exception:
            # self.logger.exception("GSSAPI error: Failed to create a GSSAPI security context for the given kerberos credentials!")
            return None

        try:
            gssapi_ctx.step(client_token)
        except Exception:
            # self.logger.exception("GSSAPI error: Failed to perform GSSAPI negotation!")
            return None

        # NOTE useful for mutual authentication, but not supported as of now
        # server_token = base64.b64encode(gssapi_token).decode('utf-8')
        return str(gssapi_ctx.initiator_name)
