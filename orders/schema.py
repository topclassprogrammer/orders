from drf_spectacular.extensions import OpenApiAuthenticationExtension


class AuthenticationScheme(OpenApiAuthenticationExtension):
    """Custom authentication scheme for token-based authentication."""
    target_class = 'backend.auth.TokenAuthentication'
    name = 'TokenAuthentication'

    def get_security_definition(self, auto_schema) -> dict:
        """Return the security definition for token-based authentication."""
        return {
            'type': 'apiKey',
            'in': 'header',
            'name': 'authorization',
        }
