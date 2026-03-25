import azure.functions as func
import logging
import jwt
import json
from datetime import datetime

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

def extract_user_info_from_token(req: func.HttpRequest):
    auth_header = req.headers.get('Authorization')
    if not auth_header:
        return None
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    
    token = parts[1]
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except Exception as e:
        logging.error(f"Token decode error: {str(e)}")
        return None

def check_user_role(token_claims, required_role):
    if not token_claims:
        return False
    
    roles = token_claims.get('roles', [])
    return required_role in roles

@app.route(route="lab4_http")
def lab4_http(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "Access Granted to Lab4 API",
             status_code=200
        )

@app.route(route="admin_only", methods=["GET"])
def admin_only(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Admin endpoint request received.')
    
    token_claims = extract_user_info_from_token(req)
    
    if not token_claims:
        return func.HttpResponse(
            json.dumps({"error": "No valid authorization token provided"}),
            status_code=401,
            mimetype="application/json"
        )
    
    user_name = token_claims.get('name', 'Unknown')
    user_roles = token_claims.get('roles', [])
    
    if not check_user_role(token_claims, 'Admin'):
        logging.warning(f"Unauthorized access attempt by user: {user_name} with roles: {user_roles}")
        return func.HttpResponse(
            json.dumps({
                "error": "Access Denied",
                "message": f"User '{user_name}' does not have Admin role",
                "user_roles": user_roles
            }),
            status_code=403,
            mimetype="application/json"
        )
    
    logging.info(f"Admin access granted to user: {user_name}")
    return func.HttpResponse(
        json.dumps({
            "message": "Access Granted to Admin-Only Feature",
            "user": user_name,
            "timestamp": datetime.utcnow().isoformat()
        }),
        status_code=200,
        mimetype="application/json"
    )

@app.route(route="userinfo", methods=["GET"])
def userinfo(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('User info endpoint request received.')
    
    token_claims = extract_user_info_from_token(req)
    
    if not token_claims:
        return func.HttpResponse(
            json.dumps({"error": "No valid authorization token provided"}),
            status_code=401,
            mimetype="application/json"
        )
    
    return func.HttpResponse(
        json.dumps({
            "name": token_claims.get('name', 'Unknown'),
            "email": token_claims.get('unique_name', 'Unknown'),
            "roles": token_claims.get('roles', []),
            "oid": token_claims.get('oid', 'Unknown')
        }),
        status_code=200,
        mimetype="application/json"
    )