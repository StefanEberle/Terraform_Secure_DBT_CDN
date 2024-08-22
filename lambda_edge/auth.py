import json
import urllib.parse
import urllib.request
import boto3
import logging
from jose import jwk, jwt
from jose.utils import base64url_decode
import time
import requests
from typing import Dict, List, Optional, Any

# Enable debug mode, True = Enable
DEBUG = False

# Configure logger
logger = logging.getLogger()
logger.setLevel(logging.ERROR if not DEBUG else logging.INFO)

# Global parameters
AWS_REGION: str = "us-east-1"
COGNITO_AWS_REGION: str = "eu-central-1"

# SSM parameters
SSM_COGNITO_DOMAIN: str = "/YOUR_PROJECT_NAME_HERE/cognito-domain"
SSM_CLIENT_ID: str = "/YOUR_PROJECT_NAME_HERE/cognito-client-id"
SSM_CLIENT_SECRET: str = "/YOUR_PROJECT_NAME_HERE/cognito-client-secret"
SSM_USER_POOL_ID: str = "/YOUR_PROJECT_NAME_HERE/cognito-user-pool-id"
SSM_CLOUDFRONT_URL: str = "/YOUR_PROJECT_NAME_HERE/cloudfront-url"

# Cookie constants
COOKIE_ID_TOKEN: str = "idToken"
COOKIE_ACCESS_TOKEN: str = "accessToken"
COOKIE_REFRESH_TOKEN: str = "refreshToken"
COOKIE_MAX_AGE_SHORT: int = 28800  # 8 hours
COOKIE_MAX_AGE_LONG: int = 604800  # 7 days

# HTTP status codes
HTTP_FOUND: str = "302"
HTTP_NO_CONTENT: str = "204"
HTTP_INTERNAL_SERVER_ERROR: str = "500"

# Initialize SSM client
ssm = boto3.client("ssm", region_name=AWS_REGION)


def get_ssm_parameter(name: str) -> str:
    """
    Fetch a parameter from AWS Systems Manager Parameter Store.

    Args:
        name: The name of the parameter.

    Returns:
        The value of the parameter.
    """
    response = ssm.get_parameter(Name=name, WithDecryption=True)
    return response["Parameter"]["Value"]


# Fetch SSM parameters
COGNITO_DOMAIN: str = get_ssm_parameter(SSM_COGNITO_DOMAIN)
CLIENT_ID: str = get_ssm_parameter(SSM_CLIENT_ID)
CLIENT_SECRET: str = get_ssm_parameter(SSM_CLIENT_SECRET)
USER_POOL_ID: str = get_ssm_parameter(SSM_USER_POOL_ID)
CLOUDFRONT_URL: str = get_ssm_parameter(SSM_CLOUDFRONT_URL)


def debug_log(message: str, *args):
    """
    Log a message if debug mode is enabled.

    Args:
        message: The message to log.
        *args: Additional arguments for message formatting.
    """
    if DEBUG:
        logger.info(message, *args)


def create_cookie(name: str, value: str, max_age: int) -> str:
    """
    Create a cookie string for create_response_with_tokens.

    Args:
        name: The name of the cookie.
        value: The value of the cookie.
        max_age: The maximum age of the cookie in seconds.

    Returns:
        The formatted cookie string.
    """
    return f"{name}={value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={max_age};"


def create_response_with_tokens(tokens: Dict[str, str]) -> Dict[str, Any]:
    """
    Create an HTTP response with auth tokens as cookies.

    Args:
        tokens: A dictionary containing the auth tokens.

    Returns:
        The HTTP response with token cookies.
    """
    # Create cookies for each token type
    # We use different expiration times for different token types
    cookies = [
        # ID token cookie
        # Used for user identification and contains claims about the user
        create_cookie(COOKIE_ID_TOKEN, tokens["id_token"], COOKIE_MAX_AGE_SHORT),
        # Access token cookie
        # Used to access protected resources on behalf of the user
        create_cookie(
            COOKIE_ACCESS_TOKEN, tokens["access_token"], COOKIE_MAX_AGE_SHORT
        ),
        # Refresh token cookie
        # Used to obtain new access and ID tokens without re-authentication
        # Has a longer lifespan than the other tokens
        create_cookie(
            COOKIE_REFRESH_TOKEN, tokens["refresh_token"], COOKIE_MAX_AGE_LONG
        ),
    ]

    # Construct the HTTP response
    return {
        # HTTP 302 Found status code
        # Indicates that the resource requested has been temporarily moved to the URL given by the Location header
        "status": HTTP_FOUND,
        "statusDescription": "Found",
        "headers": {
            # Redirect the client to the main application page
            "location": [{"key": "Location", "value": f"https://{CLOUDFRONT_URL}/"}],
            # Set the token cookies in the response
            "set-cookie": [
                {
                    "key": "Set-Cookie",
                    "value": cookie,
                    "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax",
                    # Cookie attributes for security:
                    # Path=/: Cookie is available for all paths
                    # Secure: Cookie is only sent over HTTPS
                    # HttpOnly: Cookie is not accessible via JavaScript (prevents XSS attacks)
                    # SameSite=Lax: Provides some protection against CSRF attacks while allowing some cross-site usage
                }
                for cookie in cookies
            ],
        },
    }


def generate_cognito_url(endpoint: str) -> str:
    """
    Generate a complete Cognito URL for the given endpoint.

    Args:
        endpoint: The Cognito endpoint.

    Returns:
        The complete Cognito URL.
    """
    return f"https://{COGNITO_DOMAIN}.auth.{COGNITO_AWS_REGION}.amazoncognito.com/{endpoint}"


def exchange_code_for_tokens(code: str, redirect_uri: str) -> Dict[str, str]:
    """
    Exchange the authorization code for auth tokens.

    Args:
        code: The authorization code.
        redirect_uri: The redirect URI.

    Returns:
        A dictionary containing the auth tokens.

    Raises:
        requests.RequestException: If an error occurs during the request.
    """
    # Generate the token endpoint URL
    # This is where we'll send our request to exchange the code for tokens
    token_endpoint = generate_cognito_url("oauth2/token")
    debug_log(f"Token endpoint: {token_endpoint}")

    # Prepare the payload for the token request
    # This follows the OAuth 2.0 specification for the Authorization Code grant
    payload = {
        "grant_type": "authorization_code",     # Specifies we're using the Authorization Code grant
        "client_id": CLIENT_ID,                 # The client ID of our application
        "code": code,                           # The authorization code we received
        "redirect_uri": redirect_uri,           # Must match the redirect URI used in the initial request
    }
    # Set the Content-Type header
    # This is required for POST requests with form data
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    debug_log(f"Cognito domain: {COGNITO_DOMAIN}")
    debug_log(f"Client ID: {CLIENT_ID}")
    debug_log(f"Redirect URI: {redirect_uri}")
    debug_log(f"Region: {COGNITO_AWS_REGION}")

    try:
        # Send POST request to the token endpoint
        # We use basic authentication with our client ID and secret
        response = requests.post(
            token_endpoint,
            data=payload,
            headers=headers,
            auth=(CLIENT_ID, CLIENT_SECRET),  # Basic auth with client ID and secret
        )

        # Raise an exception for HTTP errors
        # This will catch any non-2xx status codes
        response.raise_for_status()

        # Parse the JSON response
        # This should contain our access token, refresh token, and ID token
        tokens = response.json()
        debug_log(f"Received tokens from Cognito: {tokens}")
        return tokens
    except requests.RequestException as e:
        # This includes network errors, HTTP errors, and timeout errors
        logger.error(f"Error occurred: {e}")
        raise


def verify_token(
    token: str, keys: List[Dict[str, str]], token_type: str
) -> Dict[str, Any]:
    """
    Verify the authenticity and validity of a JWT token.

    Args:
        token: The JWT token to verify.
        keys: List of public keys to use for verification.
        token_type: Type of token ('access' or 'id').

    Returns:
        The decoded claims from the token if verification is successful.

    Raises:
        ValueError: If token verification fails for any reason.
    """
    try:
        # Extract the headers from the token
        headers = jwt.get_unverified_headers(token)
        kid = headers.get("kid")
        if not kid:
            raise ValueError("Token header is missing 'kid'")

        # Find the corresponding public key
        key = next((k for k in keys if k.get("kid") == kid), None)
        if not key:
            raise ValueError("Public key not found in jwks.json")

        # Construct the public key
        public_key = jwk.construct(key)

        # Verify the token's signature
        message, encoded_signature = str(token).rsplit(".", 1)
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise ValueError("Signature verification failed")

        # Decode the token claims
        claims = jwt.get_unverified_claims(token)

        debug_log(f"Token headers: {json.dumps(headers, indent=2)}")
        debug_log(f"Token claims: {json.dumps(claims, indent=2)}")
        debug_log(f"Expected CLIENT_ID: {CLIENT_ID}")
        debug_log(
            f"Expected issuer: https://cognito-idp.{COGNITO_AWS_REGION}.amazonaws.com/{USER_POOL_ID}"
        )

        # Check token expiration
        if time.time() > claims.get("exp", 0):
            raise ValueError("Token is expired")

        # Verify token-specific claims
        if token_type == "access":
            if claims.get("client_id") != CLIENT_ID:
                raise ValueError(
                    f"Token client_id mismatch. Expected {CLIENT_ID}, got {claims.get('client_id')}"
                )
        elif token_type == "id":
            if claims.get("aud") != CLIENT_ID:
                raise ValueError(
                    f"Token aud mismatch. Expected {CLIENT_ID}, got {claims.get('aud')}"
                )
        else:
            raise ValueError("Invalid token_type. Must be 'access' or 'id'")

        # Verify the token issuer
        expected_issuer = (
            f"https://cognito-idp.{COGNITO_AWS_REGION}.amazonaws.com/{USER_POOL_ID}"
        )
        if claims.get("iss") != expected_issuer:
            raise ValueError("Token was not issued by the expected issuer")

        debug_log("Token successfully verified")
        return claims

    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise


def refresh_tokens(refresh_token: str) -> Dict[str, str]:
    """
    Refresh the access and ID tokens using the refresh token.

    Args:
        refresh_token: The refresh token to use.

    Returns:
        A dictionary containing the new access and ID tokens.

    Raises:
        requests.RequestException: If the token refresh request fails.
    """
    # Generate the token endpoint URL
    token_endpoint = generate_cognito_url("oauth2/token")

    # Prepare the payload for the token refresh request
    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    }

    # Set the Content-Type header
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        # Send POST request to the token endpoint
        response = requests.post(
            token_endpoint,
            data=payload,
            headers=headers,
            auth=(CLIENT_ID, CLIENT_SECRET),
        )
        # Raise an exception for HTTP errors
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error refreshing tokens: {e}")
        raise


def handle_authorization_code(code: str, redirect_uri: str) -> Dict[str, Any]:
    """
    Handle the authorization code received from Cognito.

    Args:
        code: The authorization code.
        redirect_uri: The redirect URI used in the initial request.

    Returns:
        An HTTP response with the tokens set as cookies.
    """
    try:
        # Exchange the authorization code for tokens
        tokens = exchange_code_for_tokens(code, redirect_uri)
        # Create a response with the tokens set as cookies
        return create_response_with_tokens(tokens)
    except Exception as e:
        logger.error(f"Error exchanging code for tokens: {str(e)}")
        return create_error_response()


def get_cookie(
    headers: Dict[str, List[Dict[str, str]]], cookie_name: str
) -> Optional[Dict[str, str]]:
    """
    Extract a specific cookie from the request headers.

    Args:
        headers: The request headers.
        cookie_name: The name of the cookie to extract.

    Returns:
        The cookie dictionary if found, None otherwise.
    """
    cookie_header = headers.get("cookie", [])
    return next(
        (cookie for cookie in cookie_header if f"{cookie_name}=" in cookie["value"]),
        None,
    )


def create_error_response() -> Dict[str, str]:
    """
    Create an HTTP 500 error response.

    Returns:
        A dictionary representing the error response.
    """
    return {
        "status": HTTP_INTERNAL_SERVER_ERROR,
        "statusDescription": "Internal Server Error",
        "body": "An error occurred during authentication.",
    }


def handle_token_verification(
    id_token_cookie: Dict[str, str],
    access_token_cookie: Dict[str, str],
    refresh_token_cookie: Dict[str, str],
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Verify the ID and access tokens in the request cookies.

    Args:
        id_token_cookie: The ID token cookie.
        access_token_cookie: The access token cookie.
        refresh_token_cookie: The refresh token cookie.
        request: The original request.

    Returns:
        Either the original request if verification succeeds, a response with new tokens
        if tokens were refreshed, or a redirect to the login page if verification fails.
    """
    id_token = id_token_cookie["value"].split("idToken=")[1].split(";")[0]
    access_token = access_token_cookie["value"].split("accessToken=")[1].split(";")[0]
    refresh_token = (
        refresh_token_cookie["value"].split("refreshToken=")[1].split(";")[0]
    )

    try:
        # Fetch the JSON Web Key Set (JWKS) from Cognito
        keys_url = f"https://cognito-idp.{COGNITO_AWS_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
        with urllib.request.urlopen(keys_url) as f:
            response = f.read()
        keys = json.loads(response.decode("utf-8"))["keys"]

        try:
            # Verify both ID and Access tokens
            verify_token(id_token, keys, "id")
            verify_token(access_token, keys, "access")
            return request
        except Exception as e:
            # If tokens are expired, try to refresh them
            if str(e) == "Token is expired":
                new_tokens = refresh_tokens(refresh_token)
                new_response = create_response_with_tokens(new_tokens)
                new_response["request"] = request
                return new_response
            else:
                # If verification fails for other reasons, redirect to login
                logger.error(f"Token verification failed: {str(e)}")
                return redirect_to_login(
                    urllib.parse.quote(f"https://{CLOUDFRONT_URL}/", safe="")
                )
    except Exception as e:
        # If any other error occurs, redirect to login
        logger.error(f"Token verification failed: {str(e)}")
        return redirect_to_login(
            urllib.parse.quote(f"https://{CLOUDFRONT_URL}/", safe="")
        )


def redirect_to_login(encoded_redirect_uri: str) -> Dict[str, Any]:
    """
    Create a response that redirects to the Cognito login page.

    Args:
        encoded_redirect_uri: The URL-encoded redirect URI.

    Returns:
        A dictionary representing the redirect response.
    """
    # Generate the Cognito login URL
    login_url = generate_cognito_url(
        f"login?response_type=code&client_id={CLIENT_ID}&redirect_uri={encoded_redirect_uri}"
    )

    debug_log("Redirecting to login URL: %s", login_url)

    # Create a redirect response
    return {
        "status": HTTP_FOUND,
        "statusDescription": "Found",
        "headers": {
            "location": [{"key": "Location", "value": login_url}],
            "cache-control": [
                {"key": "Cache-Control", "value": "no-cache, no-store, must-revalidate"}
            ],
            "pragma": [{"key": "Pragma", "value": "no-cache"}],
            "expires": [{"key": "Expires", "value": "0"}],
        },
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda function handler.

    Args:
        event: The Lambda event object.
        context: The Lambda context object.

    Returns:
        The appropriate response based on the request and authentication status.
    """
    debug_log("Received event: %s", json.dumps(event))

    # Extract request details from the event
    request = event["Records"][0]["cf"]["request"]

    headers = request.get("headers", {})
    query_params = urllib.parse.parse_qs(request.get("querystring", ""))

    debug_log("Processing request for URI: %s", request["uri"])

    # Set up the redirect URI
    redirect_uri = f"https://{CLOUDFRONT_URL}/"
    encoded_redirect_uri = urllib.parse.quote(redirect_uri, safe="")

    # Check if we're receiving an authorization code
    if "code" in query_params:
        return handle_authorization_code(query_params["code"][0], redirect_uri)

    # Check for existing auth tokens in cookies
    id_token_cookie = get_cookie(headers, COOKIE_ID_TOKEN)
    access_token_cookie = get_cookie(headers, COOKIE_ACCESS_TOKEN)
    refresh_token_cookie = get_cookie(headers, COOKIE_REFRESH_TOKEN)

    # If all tokens are present, verify them
    if id_token_cookie and access_token_cookie and refresh_token_cookie:
        result = handle_token_verification(
            id_token_cookie, access_token_cookie, refresh_token_cookie, request
        )
        if isinstance(result, dict) and "request" in result:
            return result
        elif result:
            return result

    # If no valid tokens are present, redirect to login
    return redirect_to_login(encoded_redirect_uri)
