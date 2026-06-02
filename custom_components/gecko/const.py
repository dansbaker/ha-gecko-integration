"""Constants for the Gecko integration."""

DOMAIN = "gecko"

# Auth0 / OAuth — the integration now drives Auth0's hosted login pages
# directly using the mobile-app client (which is the only client allowed to
# issue tokens carrying the org_id claim required by Gecko's API).
AUTH0_DOMAIN = "gecko-prod.us.auth0.com"
MOBILE_CLIENT_ID = "IlbhNGMeYfb8ovs0gK43CjPybltA3ogH"
MOBILE_REDIRECT_URI = (
    "com.geckoportal.gecko://gecko-prod.us.auth0.com/capacitor/com.geckoportal.gecko/callback"
)
OAUTH2_AUDIENCE = "https://api.geckowatermonitor.com"
OAUTH2_ORGANIZATION = "org_8ledopyspq6wArgD"

MOBILE_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
)
# Base64-encoded JSON the mobile app sends as the auth0Client query param.
AUTH0_CLIENT_HEADER_B64 = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjIuMi4wIn0="

# API
API_BASE_URL = "https://api.geckowatermonitor.com"

# Client configuration
CONFIG_TIMEOUT = 10.0  # Default timeout for GeckoIotClient configuration loading in seconds
