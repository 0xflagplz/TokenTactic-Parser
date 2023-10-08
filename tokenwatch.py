import re
import jwt
import json

log_file_path = '/home/ubuntu/TokenTactics/capturetokenphish/TokenLog.log'

# Function to decode and verify a JWT token and format it as JSON
def decode_and_verify_jwt(jwt_token):
    try:
        decoded_token = jwt.decode(jwt_token, algorithms=['HS256'], options={"verify_signature": False})
        return json.dumps(decoded_token, indent=4)
    except jwt.ExpiredSignatureError:
        return "JWT Token has expired."
    except jwt.InvalidTokenError:
        return "Invalid JWT Token."

# Open and read the log file
with open(log_file_path, 'r') as log_file:
    lines = log_file.readlines()
    found_tokens = False
    jwt_token = None
    refresh_token = None

    for line in lines:
        if "------- Tokens -------" in line:
            found_tokens = True
        elif found_tokens and line.strip():
            if jwt_token is None:
                jwt_token = line.strip()
            else:
                refresh_token = line.strip()
                # Decode and verify JWT token
                jwt_result = decode_and_verify_jwt(jwt_token)
                decoded_jwt = json.loads(jwt_result)
                email = decoded_jwt.get("email", "Email not found in JWT")

                print("\nJWT Decoding:")
                print(jwt_result + "\n")
                print("User:", email)
                print("\n")
                print("Access Token:", jwt_token)
                print("Refresh Token:", refresh_token)
                print("-----------------")

                found_tokens = False
                jwt_token = None
                refresh_token = None
