import jwt 
from jwt import PyJWKClient # Install with `pip install PyJWT`

def verify_token(token, user_pool_id, user_pool_client_id, aws_region):
    """Verifies the JWT token using Cognito public keys"""
    issuer = f"https://cognito-idp.{aws_region}.amazonaws.com/{user_pool_id}"
    url = issuer + "/.well-known/jwks.json"
    
    jwks_client = PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(token).key

    payload = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        audience=user_pool_client_id if "access_token" in token else None,  # Only check audience for access tokens
        issuer=issuer
    )

    return payload

# Decode JWT and get user info
def get_logged_in_user(token, user_pool_id, user_pool_client_id, aws_region):
    try:
        payload = verify_token(token, user_pool_id, user_pool_client_id, aws_region)

        return {
            "user_id": payload["sub"],  # Unique Cognito User ID
            "email": payload.get("email"),
            "username": payload.get("username"),
            "groups": payload.get("cognito:groups", [])  # If using Cognito groups
        }

    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")
    

def generate_policy(principal_id, effect, resource):
    """Generates an IAM policy"""
    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    }

def get_logged_in_user_via_event(event, user_pool_id, user_pool_client_id, aws_region):
    try:
        if "headers" in event and "Authorization" in event["headers"]:
            token = event["headers"].get("Authorization")
        elif "authorizationToken" in event:
            token = event["authorizationToken"]

        if not token or not token.startswith("Bearer "):
            raise Exception("Missing or invalid Authorization header")

        token = token.split(" ")[1]  # Remove "Bearer " prefix

        return get_logged_in_user(token, user_pool_id, user_pool_client_id, aws_region)
    except Exception as e:
        raise Exception(f"Event missing data. Authorization failed: {e}")
    

def authorize_via_event(event, user_pool_id, user_pool_client_id, aws_region):
    try:
        if "headers" in event and "Authorization" in event["headers"]:
            token = event["headers"].get("Authorization")
        elif "authorizationToken" in event:
            token = event["authorizationToken"]

        if not token or not token.startswith("Bearer "):
            raise Exception("Missing or invalid Authorization header")

        token = token.split(" ")[1]  # Remove "Bearer " prefix
        payload = verify_token(token, user_pool_id, user_pool_client_id, aws_region)

        return generate_policy(payload["sub"], "Allow", event["methodArn"])
    except Exception as e:
        raise Exception(f"Authorization error. Authorization failed: {e}")
