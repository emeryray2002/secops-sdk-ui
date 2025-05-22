# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import flask
from flask import Flask, redirect, url_for, session, request, jsonify, render_template_string
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
import google.auth.exceptions
import requests as http_requests # To avoid conflict with google.auth.transport.requests.Request
import os
import json
from datetime import datetime, timedelta, timezone
from secops import SecOpsClient #
from secops.exceptions import APIError, AuthenticationError, SecOpsError #
from google.oauth2.credentials import Credentials as OAuth2Credentials
from google.auth.credentials import Scoped

# Load environment variables for local development
if os.path.exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()

app = Flask(__name__)

# Secure secret key handling
if os.environ.get("FLASK_SECRET_KEY"):
    app.secret_key = os.environ.get("FLASK_SECRET_KEY")
elif os.environ.get("FLASK_DEBUG", "False").lower() == "true":
    # In debug mode, generate a random key for the session
    app.secret_key = os.urandom(24).hex()
    app.logger.warning("Generated random secret key for debug mode. DO NOT use in production!")
else:
    # In production, require a proper secret key
    app.logger.error("FLASK_SECRET_KEY environment variable not set. This is required for production!")
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required for production use")

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = not os.environ.get("FLASK_DEBUG", "False").lower() == "true" # True in production

# Load the index.html template
INDEX_HTML_TEMPLATE = ""
try:
    with open("index.html", "r") as f:
        INDEX_HTML_TEMPLATE = f.read()
except FileNotFoundError:
    app.logger.error("index.html template file not found!")
    INDEX_HTML_TEMPLATE = "<html><body><h1>Error: Template not found</h1></body></html>"

# OAuth 2.0 configuration
CLIENT_SECRETS_FILE = None # We'll use environment variables instead
if os.path.exists("client_secret.json"): # Fallback for local testing if client_secret.json is present
    CLIENT_SECRETS_FILE = "client_secret.json"

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
FLASK_APP_URL = os.environ.get("FLASK_APP_URL", "http://localhost:8080") # Default for local

SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email', 
    'https://www.googleapis.com/auth/userinfo.profile', 
    'openid', 
    'https://www.googleapis.com/auth/cloud-platform'
]
API_ACCESS_SCOPE = 'https://www.googleapis.com/auth/cloud-platform'

# Create a credentials adapter class that implements the with_scopes method
class OAuth2CredentialsAdapter(OAuth2Credentials, Scoped):
    """Adapter for OAuth2 credentials that implements the with_scopes method required by SecOps SDK."""
    
    def with_scopes(self, scopes):
        """Return a copy of these credentials with the specified scopes."""
        # OAuth2 user credentials can't change their scopes, so we just return self
        return self
        
    def requires_scopes(self):
        """Returns True if scopes are required for these credentials, False otherwise."""
        return False

# --- OAuth Routes ---
def get_oauth_flow():
    redirect_uri = FLASK_APP_URL.rstrip('/') + url_for('oauth2callback')
    if CLIENT_SECRETS_FILE:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
    elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri],
                    "javascript_origins": [FLASK_APP_URL.rstrip('/')]
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
    else:
        raise ValueError("OAuth client credentials not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables or provide client_secret.json.")
    return flow

@app.route('/login')
def login():
    flow = get_oauth_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent' # Force prompt for refresh token
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('oauth_state')
    flow = get_oauth_flow()
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        app.logger.error(f"Error fetching token: {e}")
        return "Failed to fetch OAuth token.", 400

    if not state or state != request.args.get('state'):
        app.logger.error(f"State mismatch: session_state={state}, request_state={request.args.get('state')}")
        # For some reason, state can be missing in App Engine Flexible env with IAP,
        # but credentials flow should still work. If credentials are not there, it will fail.
        # If flow.credentials exists, proceed.
        if not flow.credentials:
            return redirect(url_for('login')) # Or an error page

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    # Get user info
    try:
        userinfo_service = http_requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        userinfo = userinfo_service.json()
        session['user_email'] = userinfo.get('email')
        session['user_name'] = userinfo.get('name')
    except Exception as e:
        app.logger.error(f"Error fetching user info: {e}")
        # Continue even if userinfo fails, credentials might still be valid for API calls

    # Initialize environments and history if not present
    if 'environments' not in session:
        session['environments'] = []
    if 'history' not in session:
        session['history'] = []

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    credentials_dict = session.get('credentials')
    if credentials_dict:
        token = credentials_dict.get('token')
        if token:
            revoke = http_requests.post('https://oauth2.googleapis.com/revoke',
                                params={'token': token},
                                headers={'content-type': 'application/x-www-form-urlencoded'})
            status_code = getattr(revoke, 'status_code', None)
            if status_code != 200:
                app.logger.error(f"Failed to revoke token: Status {status_code}, Body {revoke.text}")

    session.clear()
    return redirect(url_for('index'))

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': getattr(credentials, 'id_token', None),
            'expiry': credentials.expiry.isoformat() if credentials.expiry else None}

def get_credentials_from_session():
    credentials_dict = session.get('credentials')
    if not credentials_dict:
        return None

    # Check for token expiry
    expiry_str = credentials_dict.get('expiry')
    if expiry_str:
        expiry_dt = datetime.fromisoformat(expiry_str)
        # Make expiry_dt timezone-aware if it's naive
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        if expiry_dt <= datetime.now(timezone.utc) + timedelta(minutes=1): # Refresh if expiring soon
            if credentials_dict.get('refresh_token'):
                try:
                    creds = Credentials(
                        token=credentials_dict.get('token'),
                        refresh_token=credentials_dict.get('refresh_token'),
                        token_uri=credentials_dict.get('token_uri'),
                        client_id=credentials_dict.get('client_id'),
                        client_secret=credentials_dict.get('client_secret'),
                        scopes=credentials_dict.get('scopes')
                    )
                    creds.refresh(Request())
                    session['credentials'] = credentials_to_dict(creds)
                    return creds
                except google.auth.exceptions.RefreshError as e:
                    app.logger.error(f"OAuth refresh token error: {e}")
                    return None # Will trigger re-login
            else: # No refresh token
                return None # Will trigger re-login

    return Credentials(
        token=credentials_dict.get('token'),
        refresh_token=credentials_dict.get('refresh_token'),
        id_token=credentials_dict.get('id_token'),
        token_uri=credentials_dict.get('token_uri'),
        client_id=credentials_dict.get('client_id'),
        client_secret=credentials_dict.get('client_secret'),
        scopes=credentials_dict.get('scopes')
    )

# --- Main App Route ---
@app.route('/')
def index():
    if 'credentials' not in session:
        return render_template_string(LOGIN_PAGE_TEMPLATE)

    creds = get_credentials_from_session()
    if not creds or not creds.valid or API_ACCESS_SCOPE not in creds.scopes:
        # If not valid or doesn't have the API scope, attempt re-login for consent
        return redirect(url_for('login'))

    user_email = session.get('user_email', 'Not logged in')
    user_name = session.get('user_name', 'User')
    
    # Pass user info and app URL to the template
    return render_template_string(
        INDEX_HTML_TEMPLATE,
        user_email=user_email, 
        user_name=user_name,
        flask_app_url=FLASK_APP_URL.rstrip('/')
    )

LOGIN_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SecOps SDK UI</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { theme: { extend: { darkMode: 'class' } } }
        document.documentElement.classList.add('dark');
    </script>
</head>
<body class="bg-slate-900 text-slate-300 flex items-center justify-center h-screen">
    <div class="text-center p-8 bg-slate-800 rounded-lg shadow-xl">
        <h1 class="text-3xl font-bold mb-6 text-sky-400">SecOps SDK UI</h1>
        <p class="mb-8">Please login with your Google Account to continue.</p>
        <a href="{{ url_for('login') }}"
           class="bg-sky-500 hover:bg-sky-600 text-white font-bold py-3 px-6 rounded-lg text-lg transition duration-150 ease-in-out">
            Login with Google
        </a>
    </div>
</body>
</html>
"""


# --- API Routes for SDK Tools ---
def _get_chronicle_client(env_index):
    """Get a Chronicle client using OAuth credentials."""
    # Import necessary libraries
    from google.auth.transport.requests import Request
    import google.auth.transport.requests
    
    # Get credentials from session
    creds_dict = session.get('credentials')
    if not creds_dict:
        raise AuthenticationError("User not authenticated or token expired.")

    # Get environment details
    environments = session.get('environments', [])
    if not environments or not (0 <= env_index < len(environments)):
        raise ValueError("Selected environment is invalid or not found.")
    env = environments[env_index]
    
    try:
        # Create OAuth credentials from session data
        oauth_creds = OAuth2Credentials(
            token=creds_dict.get('token'),
            refresh_token=creds_dict.get('refresh_token'),
            token_uri=creds_dict.get('token_uri'),
            client_id=creds_dict.get('client_id'),
            client_secret=creds_dict.get('client_secret'),
            scopes=creds_dict.get('scopes'),
        )
        
        # Ensure the token is fresh
        if oauth_creds.expired and oauth_creds.refresh_token:
            request = google.auth.transport.requests.Request()
            oauth_creds.refresh(request)
            # Update session with refreshed token
            session['credentials'] = credentials_to_dict(oauth_creds)

        # Create our adapter that implements with_scopes
        adapter_creds = OAuth2CredentialsAdapter(
            token=oauth_creds.token,
            refresh_token=oauth_creds.refresh_token,
            token_uri=oauth_creds.token_uri,
            client_id=oauth_creds.client_id,
            client_secret=oauth_creds.client_secret,
            scopes=oauth_creds.scopes,
            expiry=oauth_creds.expiry
        )

        region = env['region']
        customer_id = env['customerId']
        project_id = env['projectId']
        
        app.logger.info(f"Using OAuth credentials adapter for SecOpsClient with customer_id={customer_id}, project_id={project_id}, region={region}")
        
        # Import the SDK here to ensure it uses our credential setup
        from secops import SecOpsClient
        
        # Initialize with our adapter credentials
        secops_client = SecOpsClient(credentials=adapter_creds)
        
        # Special handling for staging/dev environments
        if region in ["dev", "staging"]:
            app.logger.info(f"Using special handling for {region} environment with forced 'us' location")
            
            # Import ChronicleClient directly
            from secops.chronicle import ChronicleClient
            
            # Create a new environment config with modified region
            env_config = {
                "name": env["name"],
                "customerId": customer_id,
                "projectId": project_id,
                "region": "us"  # Force location to be "us"
            }
            
            # Create Chronicle client through SecOpsClient with "us" region
            chronicle_client = secops_client.chronicle(
                customer_id=customer_id,
                project_id=project_id,
                region="us"  # Force "us" as the region for the API path
            )
            
            # Manually override the base_url for staging/dev
            if region == "dev":
                chronicle_client.base_url = "https://dev-chronicle.sandbox.googleapis.com/v1alpha"
            elif region == "staging":
                chronicle_client.base_url = "https://staging-chronicle.sandbox.googleapis.com/v1alpha"
            
            # Make sure instance_id uses "us" location
            chronicle_client.instance_id = f"projects/{project_id}/locations/us/instances/{customer_id}"
            
            app.logger.info(f"Chronicle client created with instance_id={chronicle_client.instance_id} and base_url={chronicle_client.base_url}")
        else:
            # Standard production regions - use the factory method from SecOpsClient
            chronicle_client = secops_client.chronicle(
                customer_id=customer_id,
                project_id=project_id,
                region=region
            )
        
        return chronicle_client
    except Exception as e:
        app.logger.error(f"Failed to initialize Chronicle client: {e}", exc_info=True)
        raise SecOpsError(f"Failed to initialize Chronicle client: {str(e)}")

def _add_to_history(tool_name, params):
    """Add an entry to the session history."""
    app.logger.info(f"Adding to history: {tool_name}")
    
    history = session.get('history', [])
    max_history_items = 20 # Configurable, keep small due to cookie size
    
    # Remove oldest if max size reached
    if len(history) >= max_history_items:
        history.pop(0)
        
    # Create a new entry with current timestamp
    history_entry = {
        "tool": tool_name,
        "params": params,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    history.append(history_entry)
    session['history'] = history
    session.modified = True
    
    app.logger.info(f"History updated, now contains {len(history)} items")


def _handle_sdk_call(tool_name, sdk_function, params, request_data):
    """Wrapper to handle SDK calls, history, and errors."""
    try:
        # Add to history before making the call
        _add_to_history(tool_name, request_data)
        
        # Attempt to make the SDK call
        app.logger.info(f"Making SDK call for {tool_name} with params: {params}")
        result = sdk_function(**params)
        app.logger.info(f"SDK call for {tool_name} successful")
        
        return jsonify({"success": True, "data": result, "env_status": "ok"})
    except APIError as e:
        app.logger.error(f"API Error in {tool_name}: {e}")
        # Check for authentication-related errors
        error_msg = str(e)
        if "unauthorized" in error_msg.lower() or "unauthenticated" in error_msg.lower() or "permission" in error_msg.lower():
            return jsonify({"success": False, "error": f"Authentication error: {error_msg}", "env_status": "auth_error"}), 401
        
        # Return sanitized error for API errors (these are generally safe to show to users)
        return jsonify({"success": False, "error": error_msg, "env_status": "error"}), 400
    except SecOpsError as e:
        app.logger.error(f"SecOps Error in {tool_name}: {e}")
        error_msg = str(e)
        if "authentication" in error_msg.lower() or "credentials" in error_msg.lower():
            return jsonify({"success": False, "error": f"Authentication error: {error_msg}", "env_status": "auth_error"}), 401
        
        # Return sanitized error for SecOps errors (these are generally safe to show to users)
        return jsonify({"success": False, "error": error_msg, "env_status": "error"}), 400
    except ValueError as e:
        app.logger.error(f"Value Error in {tool_name}: {e}")
        # Value errors are typically due to invalid input, safe to return to user
        return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400
    except AuthenticationError as e:
        app.logger.error(f"Authentication Error in {tool_name}: {e}")
        # Don't expose the raw error message for auth errors
        return jsonify({"success": False, "error": "Authentication required. Please re-login.", "env_status": "auth_error"}), 401
    except Exception as e:
        # For unexpected errors, log the full details but return a generic message
        app.logger.error(f"Unexpected error in {tool_name}: {e}", exc_info=True)
        error_str = str(e).lower()
        
        # Check if it's a network or connection error
        if "network" in error_str or "connection" in error_str or "connect" in error_str or "socket" in error_str:
            return jsonify({"success": False, "error": "Network connection error. Please check your internet connection and try again.", "env_status": "error"}), 503
        
        # For production, don't expose raw error messages for unexpected errors
        if os.environ.get("FLASK_DEBUG", "False").lower() == "true":
            # In debug mode, include the actual error for troubleshooting
            return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}", "env_status": "error"}), 500
        else:
            # In production, use a generic message
            return jsonify({"success": False, "error": "An unexpected server error occurred. Please try again or contact support.", "env_status": "error"}), 500

# --- Environment Management API ---
@app.route('/api/environments', methods=['GET'])
def get_environments():
    creds = get_credentials_from_session()
    if not creds: return jsonify({"error": "Unauthorized"}), 401
    return jsonify(session.get('environments', []))

@app.route('/api/environments', methods=['POST'])
def add_environment():
    creds = get_credentials_from_session()
    if not creds: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    if not all(k in data for k in ('name', 'customerId', 'projectId', 'region')):
        return jsonify({"error": "Missing required fields"}), 400

    environments = session.get('environments', [])
    # Check for duplicate name or combination of IDs/region
    if any(env['name'] == data['name'] for env in environments):
         return jsonify({"error": "Environment name already exists"}), 400
    
    new_env = {
        "name": data['name'],
        "customerId": data['customerId'],
        "projectId": data['projectId'],
        "region": data['region'],
        "status": "unknown" # Initial status
    }
    environments.append(new_env)
    session['environments'] = environments
    session.modified = True
    return jsonify(new_env), 201

@app.route('/api/environments/<int:env_index>', methods=['PUT'])
def update_environment(env_index):
    creds = get_credentials_from_session()
    if not creds: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    environments = session.get('environments', [])
    if not (0 <= env_index < len(environments)):
        return jsonify({"error": "Environment not found"}), 404
    
    # Check for duplicate name if name is being changed
    if 'name' in data and data['name'] != environments[env_index]['name']:
        if any(env['name'] == data['name'] for i, env in enumerate(environments) if i != env_index):
            return jsonify({"error": "Environment name already exists"}), 400

    environments[env_index].update(data)
    environments[env_index]["status"] = "unknown" # Reset status on update
    session['environments'] = environments
    session.modified = True
    return jsonify(environments[env_index])

@app.route('/api/environments/<int:env_index>', methods=['DELETE'])
def delete_environment(env_index):
    creds = get_credentials_from_session()
    if not creds: return jsonify({"error": "Unauthorized"}), 401
    environments = session.get('environments', [])
    if not (0 <= env_index < len(environments)):
        return jsonify({"error": "Environment not found"}), 404
    
    deleted_env = environments.pop(env_index)
    session['environments'] = environments
    session.modified = True
    return jsonify(deleted_env)

@app.route('/api/history', methods=['GET'])
def get_history():
    creds = get_credentials_from_session()
    if not creds: return jsonify({"error": "Unauthorized"}), 401
    
    # Log the history for debugging
    history = session.get('history', [])
    app.logger.info(f"Returning history with {len(history)} items")
    
    return jsonify(history)

@app.route('/api/history', methods=['DELETE'])
def clear_history():
    creds = get_credentials_from_session()
    if not creds: return jsonify({"error": "Unauthorized"}), 401
    
    app.logger.info("Clearing history")
    session['history'] = []
    session.modified = True
    
    return jsonify({"message": "History cleared"})

# --- Tool Specific API Endpoints ---
# Each will call _get_chronicle_client and then _handle_sdk_call

def parse_time_params(data):
    params = {}
    if data.get('start_time'):
        params['start_time'] = datetime.fromisoformat(data['start_time'].replace('Z', '+00:00'))
    if data.get('end_time'):
        params['end_time'] = datetime.fromisoformat(data['end_time'].replace('Z', '+00:00'))
    if data.get('time_window_value') and data.get('time_window_unit'):
        # Calculate start/end from time_window if specific times not given
        if not params.get('start_time') and not params.get('end_time'):
            delta_value = int(data['time_window_value'])
            unit = data['time_window_unit']
            if unit == 'hours':
                delta = timedelta(hours=delta_value)
            elif unit == 'days':
                delta = timedelta(days=delta_value)
            elif unit == 'minutes':
                delta = timedelta(minutes=delta_value)
            else: # default to hours
                delta = timedelta(hours=delta_value)
            
            params['end_time'] = datetime.now(timezone.utc)
            params['start_time'] = params['end_time'] - delta
        elif not params.get('start_time') and params.get('end_time'):
             # end_time is provided, calculate start_time
            delta_value = int(data['time_window_value'])
            unit = data['time_window_unit']
            if unit == 'hours':
                delta = timedelta(hours=delta_value)
            elif unit == 'days':
                delta = timedelta(days=delta_value)
            elif unit == 'minutes':
                delta = timedelta(minutes=delta_value)
            else: # default to hours
                delta = timedelta(hours=delta_value)
            params['start_time'] = params['end_time'] - delta
        # If start_time is provided but not end_time, time_window can calculate end_time (less common)
        # Or, if both start and end are provided, they take precedence over time_window.
    
    # If after all that, times are still missing, default to a reasonable window (e.g., last 24 hours)
    if 'end_time' not in params:
        params['end_time'] = datetime.now(timezone.utc)
    if 'start_time' not in params:
         params['start_time'] = params['end_time'] - timedelta(hours=data.get('time_window_value', 24) if data.get('time_window_unit') == 'hours' else 24)


    return params

# --- Search Tools ---
@app.route('/api/tools/search_udm_events', methods=['POST'])
def tool_search_udm():
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "No request data provided", "env_status": "error"}), 400
        
        # Validate required parameters
        env_index = data.get('environmentIndex')
        if env_index is None:
            return jsonify({"success": False, "error": "Missing environmentIndex parameter", "env_status": "error"}), 400
        
        # Get client
        try:
            chronicle_client = _get_chronicle_client(env_index)
        except (AuthenticationError, ValueError, SecOpsError) as e:
            return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400
        
        # Parse time parameters
        params = parse_time_params(data)
        
        # Set query parameters based on query type
        query_type = data.get('query_type', 'udm')
        if query_type == 'udm':
            if not data.get('query'):
                return jsonify({"success": False, "error": "Missing UDM query parameter", "env_status": "error"}), 400
            params['query'] = data['query']
            
            # Handle CSV export
            if data.get('csv_export') and data.get('fields_for_csv'):
                params['fields'] = [f.strip() for f in data['fields_for_csv'].split(',')]
                return _handle_sdk_call("Search UDM (CSV)", chronicle_client.fetch_udm_search_csv, params, data)
            else:
                if data.get('max_events'): 
                    params['max_events'] = int(data['max_events'])
                return _handle_sdk_call("Search UDM", chronicle_client.search_udm, params, data)
        elif query_type == 'nl':
            if not data.get('nl_query'):
                return jsonify({"success": False, "error": "Missing Natural Language query parameter", "env_status": "error"}), 400
            params['text'] = data['nl_query']
            if data.get('max_events'): 
                params['max_events'] = int(data['max_events'])
            return _handle_sdk_call("Natural Language Search", chronicle_client.nl_search, params, data)
        else:
            return jsonify({"success": False, "error": f"Invalid query_type: {query_type}", "env_status": "error"}), 400
            
    except Exception as e:
        app.logger.error(f"Error in search_udm: {e}", exc_info=True)
        return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}", "env_status": "error"}), 500

@app.route('/api/tools/search_stats', methods=['POST'])
def tool_search_stats():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = parse_time_params(data)
    if data.get('query'): params['query'] = data['query']
    if data.get('max_events'): params['max_events'] = int(data['max_events'])
    if data.get('max_values'): params['max_values'] = int(data['max_values'])
    
    return _handle_sdk_call("Get Statistics", chronicle_client.get_stats, params, data)

# --- Entity Tools ---
@app.route('/api/tools/entity_summary', methods=['POST'])
def tool_entity_summary():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = parse_time_params(data)
    if data.get('entity_value'): params['value'] = data['entity_value']
    if data.get('preferred_entity_type'): params['preferred_entity_type'] = data['preferred_entity_type']
    # include_all_udm_types, page_size, page_token are optional with defaults
    
    return _handle_sdk_call("Summarize Entity", chronicle_client.summarize_entity, params, data)

# --- IoC Tools ---
@app.route('/api/tools/list_iocs', methods=['POST'])
def tool_list_iocs():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = parse_time_params(data)
    if data.get('max_matches'): params['max_matches'] = int(data['max_matches'])
    params['add_mandiant_attributes'] = data.get('add_mandiant_attributes', True)
    params['prioritized_only'] = data.get('prioritized_only', False)
        
    return _handle_sdk_call("List IoCs", chronicle_client.list_iocs, params, data)

# --- Log Ingestion Tools ---
@app.route('/api/tools/log_ingest', methods=['POST'])
def tool_log_ingest():
    data = request.json # For file uploads, this would need to be handled differently (Flask's request.files)
                       # For simplicity, assuming log content is passed as text or JSON in `log_message`
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if data.get('log_type'): params['log_type'] = data['log_type']
    if data.get('log_message'): params['log_message'] = data['log_message'] # Could be single string or list of strings for batch
    if data.get('log_entry_time'): params['log_entry_time'] = datetime.fromisoformat(data['log_entry_time'].replace('Z', '+00:00'))
    if data.get('collection_time'): params['collection_time'] = datetime.fromisoformat(data['collection_time'].replace('Z', '+00:00'))
    if data.get('forwarder_id'): params['forwarder_id'] = data['forwarder_id']
    params['force_log_type'] = data.get('force_log_type', False)
    if data.get('labels'): # Expects dict
        try:
            params['labels'] = json.loads(data['labels']) if isinstance(data['labels'], str) else data['labels']
        except json.JSONDecodeError:
            return jsonify({"success": False, "error": "Labels must be a valid JSON string or object.", "env_status": "error"}), 400

    return _handle_sdk_call("Ingest Log", chronicle_client.ingest_log, params, data)

@app.route('/api/tools/log_ingest_udm', methods=['POST'])
def tool_log_ingest_udm():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if data.get('udm_events'): # Expects dict or list of dicts
        try:
            params['udm_events'] = json.loads(data['udm_events']) if isinstance(data['udm_events'], str) else data['udm_events']
        except json.JSONDecodeError:
             return jsonify({"success": False, "error": "UDM events must be a valid JSON string or object/array.", "env_status": "error"}), 400
    
    return _handle_sdk_call("Ingest UDM", chronicle_client.ingest_udm, params, data)

@app.route('/api/tools/log_types_list', methods=['POST'])
def tool_log_types_list():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if data.get('search_term'):
        # SDK function search_log_types doesn't take client as first arg
        # and is not part of ChronicleClient class in the provided snippets
        # Assuming it's meant to be chronicle_client.search_log_types
        try:
            result = chronicle_client.search_log_types(search_term=data['search_term'])
            _add_to_history("List Log Types (Search)", data)
            return jsonify({"success": True, "data": [lt.__dict__ for lt in result], "env_status": "ok"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400
    else:
        # Assuming chronicle_client.get_all_log_types
        try:
            result = chronicle_client.get_all_log_types()
            _add_to_history("List Log Types (All)", data)
            return jsonify({"success": True, "data": [lt.__dict__ for lt in result], "env_status": "ok"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400


# --- Rule Management Tools ---
@app.route('/api/tools/rule_list', methods=['POST'])
def tool_rule_list():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    return _handle_sdk_call("List Rules", chronicle_client.list_rules, {}, data)

@app.route('/api/tools/rule_get', methods=['POST'])
def tool_rule_get():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'rule_id': data.get('rule_id')}
    return _handle_sdk_call("Get Rule", chronicle_client.get_rule, params, data)

@app.route('/api/tools/rule_create', methods=['POST'])
def tool_rule_create():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'rule_text': data.get('rule_text')}
    return _handle_sdk_call("Create Rule", chronicle_client.create_rule, params, data)

@app.route('/api/tools/rule_update', methods=['POST'])
def tool_rule_update():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'rule_id': data.get('rule_id'), 'rule_text': data.get('rule_text')}
    return _handle_sdk_call("Update Rule", chronicle_client.update_rule, params, data)

@app.route('/api/tools/rule_enable', methods=['POST'])
def tool_rule_enable():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'rule_id': data.get('rule_id'), 'enabled': data.get('enabled_state', True)}
    return _handle_sdk_call("Enable/Disable Rule", chronicle_client.enable_rule, params, data)

@app.route('/api/tools/rule_delete', methods=['POST'])
def tool_rule_delete():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'rule_id': data.get('rule_id'), 'force': data.get('force_delete', False)}
    return _handle_sdk_call("Delete Rule", chronicle_client.delete_rule, params, data)

@app.route('/api/tools/rule_validate', methods=['POST'])
def tool_rule_validate():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'rule_text': data.get('rule_text')}
    # validate_rule returns a ValidationResult object, need to convert to dict
    try:
        _add_to_history("Validate Rule", data)
        result = chronicle_client.validate_rule(**params)
        return jsonify({"success": True, "data": result._asdict(), "env_status": "ok"})
    except Exception as e: # Catch specific errors if needed
        return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400
        
@app.route('/api/tools/rule_search', methods=['POST'])
def tool_rule_search():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'query': data.get('regex_query')}
    return _handle_sdk_call("Search Rules", chronicle_client.search_rules, params, data)


# --- Alert Management Tools ---
@app.route('/api/tools/alert_get', methods=['POST'])
def tool_alert_get(): # This is for rule alerts, not the general get_alerts
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = parse_time_params(data) # get_alerts from SDK needs time
    if data.get('snapshot_query'): params['snapshot_query'] = data['snapshot_query']
    if data.get('baseline_query'): params['baseline_query'] = data['baseline_query']
    if data.get('max_alerts'): params['max_alerts'] = int(data['max_alerts'])
    # SDK get_alerts not get_alert by id
    return _handle_sdk_call("Get Alerts", chronicle_client.get_alerts, params, data)

@app.route('/api/tools/alert_get_single', methods=['POST'])
def tool_alert_get_single():
    """Get details for a single alert by ID."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if not data.get('alert_id_to_get'):
        return jsonify({"success": False, "error": "Missing alert ID parameter", "env_status": "error"}), 400
    
    params['alert_id'] = data['alert_id_to_get']
    
    # Optional parameters
    if data.get('include_detections_in_alert'):
        params['include_detections'] = data['include_detections_in_alert']
    
    return _handle_sdk_call("Get Alert Details", chronicle_client.get_alert, params, data)

@app.route('/api/tools/alert_update_single', methods=['POST'])
def tool_alert_update_single():
    """Update a single alert's fields."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if not data.get('alert_id_to_update'):
        return jsonify({"success": False, "error": "Missing alert ID parameter", "env_status": "error"}), 400
    
    params['alert_id'] = data['alert_id_to_update']
    
    # Optional fields to update
    update_fields = [
        ('confidence_score', 'confidence'),
        ('reason_for_closing', 'closing_reason'),
        ('reputation', 'reputation'),
        ('priority_level', 'priority'),
        ('status_of_alert', 'status'),
        ('verdict_on_alert', 'verdict'),
        ('risk_score', 'risk_score'),
        ('disregarded_alert', 'disregarded'),
        ('severity_score', 'severity'),
        ('comment_text', 'comment'),
        ('root_cause_text', 'root_cause')
    ]
    
    for frontend_field, sdk_field in update_fields:
        if frontend_field in data and data[frontend_field] not in [None, ""]:
            # Convert numeric values if needed
            if sdk_field in ['confidence', 'risk_score', 'severity']:
                params[sdk_field] = int(data[frontend_field])
            # Convert boolean values
            elif sdk_field == 'disregarded':
                params[sdk_field] = bool(data[frontend_field])
            else:
                params[sdk_field] = data[frontend_field]
    
    return _handle_sdk_call("Update Alert", chronicle_client.update_alert, params, data)

# --- Case Management Tools ---
@app.route('/api/tools/case_get_details', methods=['POST'])
def tool_case_get_details():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    case_ids_str = data.get('case_ids', '')
    params = {'case_ids': [cid.strip() for cid in case_ids_str.split(',') if cid.strip()]}
    if not params['case_ids']:
        return jsonify({"success": False, "error": "No case IDs provided.", "env_status": "error"}), 400
    # get_cases returns a CaseList object
    try:
        _add_to_history("Get Case Details", data)
        result_caselist = chronicle_client.get_cases(**params)
        # Convert CaseList and its Case objects to dicts for JSON response
        cases_as_dicts = []
        for case_obj in result_caselist.cases:
            case_dict = {
                "id": case_obj.id,
                "display_name": case_obj.display_name,
                "stage": case_obj.stage,
                "priority": case_obj.priority,
                "status": case_obj.status,
                "alert_ids": case_obj.alert_ids,
                "soar_platform_info": case_obj.soar_platform_info.__dict__ if case_obj.soar_platform_info else None
            }
            cases_as_dicts.append(case_dict)
        return jsonify({"success": True, "data": {"cases": cases_as_dicts}, "env_status": "ok"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400


# --- Data Export Tools ---
@app.route('/api/tools/export_log_types_list', methods=['POST'])
def tool_export_log_types_list():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = parse_time_params(data)
    if data.get('page_size'): params['page_size'] = int(data['page_size'])
    # SDK fetch_available_log_types returns dict with AvailableLogType objects
    try:
        _add_to_history("List Exportable Log Types", data)
        result = chronicle_client.fetch_available_log_types(**params)
        # Convert AvailableLogType objects to dicts
        result['available_log_types'] = [vars(alt) for alt in result.get('available_log_types', [])]
        return jsonify({"success": True, "data": result, "env_status": "ok"})
    except Exception as e:
         return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400

@app.route('/api/tools/export_create', methods=['POST'])
def tool_export_create():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = parse_time_params(data)
    if data.get('gcs_bucket'): params['gcs_bucket'] = data['gcs_bucket']
    if data.get('log_type_to_export'): params['log_type'] = data['log_type_to_export']
    params['export_all_logs'] = data.get('export_all_logs', False)
    return _handle_sdk_call("Create Data Export", chronicle_client.create_data_export, params, data)

@app.route('/api/tools/export_status', methods=['POST'])
def tool_export_status():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'data_export_id': data.get('export_id')}
    return _handle_sdk_call("Get Export Status", chronicle_client.get_data_export, params, data)

@app.route('/api/tools/export_cancel', methods=['POST'])
def tool_export_cancel():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    params = {'data_export_id': data.get('export_id')}
    return _handle_sdk_call("Cancel Data Export", chronicle_client.cancel_data_export, params, data)

# --- Gemini AI Tools ---
@app.route('/api/tools/gemini_query', methods=['POST'])
def tool_gemini_query():
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {'query': data.get('gemini_query_text')}
    if data.get('conversation_id'): params['conversation_id'] = data['conversation_id']
    # context_uri and context_body are optional with defaults in SDK
    
    # chronicle.gemini returns a GeminiResponse object
    try:
        # Use consistent tool name to match the frontend tool ID
        app.logger.info("Adding Gemini AI query to history")
        _add_to_history("Query Gemini AI", data)
        gemini_response_obj = chronicle_client.gemini(**params)
        
        # Convert GeminiResponse object to a serializable dict
        response_dict = {
            "name": gemini_response_obj.name,
            "input_query": gemini_response_obj.input_query,
            "create_time": gemini_response_obj.create_time,
            "blocks": [vars(block) for block in gemini_response_obj.blocks],
            "suggested_actions": [
                {
                    "display_text": sa.display_text,
                    "action_type": sa.action_type,
                    "use_case_id": sa.use_case_id,
                    "navigation": vars(sa.navigation) if sa.navigation else None,
                } for sa in gemini_response_obj.suggested_actions
            ],
            "references": [vars(ref) for ref in gemini_response_obj.references],
            "groundings": gemini_response_obj.groundings,
            # "raw_response": gemini_response_obj.get_raw_response() # Potentially very large
        }
        if data.get('output_raw_gemini', False):
             response_dict["raw_response_full"] = gemini_response_obj.get_raw_response()

        return jsonify({"success": True, "data": response_dict, "env_status": "ok"})
    except (APIError, SecOpsError, ValueError) as e:
        app.logger.error(f"Error in Gemini Query: {e}")
        # Check for specific opt-in message
        if "users must opt-in before using Gemini" in str(e):
             return jsonify({"success": False, "error": "Gemini requires opt-in. Please use the 'Opt-in to Gemini' tool or enable it in your Chronicle settings.", "env_status": "error", "gemini_opt_in_required": True}), 400
        return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error in Gemini Query: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An unexpected server error occurred.", "env_status": "error"}), 500


@app.route('/api/tools/gemini_opt_in', methods=['POST'])
def tool_gemini_opt_in():
    data = request.json # No specific params needed from client for opt-in itself
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    try:
        _add_to_history("Opt-in to Gemini", {})
        opt_in_successful = chronicle_client.opt_in_to_gemini()
        if opt_in_successful:
            return jsonify({"success": True, "data": {"message": "Successfully opted into Gemini for this session/user preference."}, "env_status": "ok"})
        else:
            return jsonify({"success": False, "error": "Gemini opt-in failed. This may be due to insufficient permissions.", "env_status": "error"}), 400
    except APIError as e:
        app.logger.error(f"API Error during Gemini opt-in: {e}")
        return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error during Gemini opt-in: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An unexpected server error occurred during Gemini opt-in.", "env_status": "error"}), 500

# Debug endpoints that should only be available in debug mode
def register_debug_endpoints(app):
    @app.route('/api/debug/auth_status', methods=['GET'])
    def debug_auth_status():
        try:
            creds = get_credentials_from_session()
            if not creds:
                return jsonify({
                    "authenticated": False,
                    "message": "No credentials found in session."
                })
            
            # Check if credentials are valid
            is_valid = creds.valid
            if not is_valid and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    is_valid = True
                    session['credentials'] = credentials_to_dict(creds)
                except Exception as e:
                    return jsonify({
                        "authenticated": False,
                        "message": f"Credentials expired and refresh failed: {str(e)}",
                        "scopes": creds.scopes
                    })
            
            return jsonify({
                "authenticated": is_valid,
                "token_expiry": creds.expiry.isoformat() if creds.expiry else None,
                "has_refresh_token": creds.refresh_token is not None,
                "scopes": creds.scopes,
                "has_cloud_platform_scope": "https://www.googleapis.com/auth/cloud-platform" in creds.scopes,
                "project_id": creds.client_id.split('-')[0] if creds.client_id else None
            })
        except Exception as e:
            return jsonify({
                "authenticated": False,
                "error": str(e)
            }), 500

    @app.route('/api/debug/test_secops_auth', methods=['GET'])
    def debug_test_secops_auth():
        """
        Debug endpoint to test SecOps SDK authentication with OAuth credentials.
        """
        try:
            # Get credentials from session
            creds_dict = session.get('credentials')
            if not creds_dict:
                return jsonify({
                    "success": False,
                    "error": "No credentials found in session",
                    "message": "Please login first"
                }), 401
            
            # Create OAuth credentials object
            from google.auth.transport.requests import Request
            
            oauth_creds = OAuth2Credentials(
                token=creds_dict.get('token'),
                refresh_token=creds_dict.get('refresh_token'),
                token_uri=creds_dict.get('token_uri'),
                client_id=creds_dict.get('client_id'),
                client_secret=creds_dict.get('client_secret'),
                scopes=creds_dict.get('scopes')
            )
            
            # Refresh if needed
            if oauth_creds.expired and oauth_creds.refresh_token:
                oauth_creds.refresh(Request())
                session['credentials'] = credentials_to_dict(oauth_creds)
            
            # Create our adapter with the with_scopes method
            adapter_creds = OAuth2CredentialsAdapter(
                token=oauth_creds.token,
                refresh_token=oauth_creds.refresh_token,
                token_uri=oauth_creds.token_uri,
                client_id=oauth_creds.client_id,
                client_secret=oauth_creds.client_secret,
                scopes=oauth_creds.scopes,
                expiry=oauth_creds.expiry
            )
            
            # Try to initialize SecOpsClient with our adapter
            try:
                from secops import SecOpsClient
                secops_client = SecOpsClient(credentials=adapter_creds)
                
                # Check if with_scopes method is available
                has_with_scopes = hasattr(adapter_creds, 'with_scopes')
                
                # Get basic details for response
                creds_info = {
                    "token_valid": not oauth_creds.expired,
                    "has_refresh_token": bool(oauth_creds.refresh_token),
                    "scopes": oauth_creds.scopes,
                    "client_id": oauth_creds.client_id,
                    "has_with_scopes": has_with_scopes,
                    "adapter_class": adapter_creds.__class__.__name__
                }
                
                return jsonify({
                    "success": True,
                    "message": "Successfully initialized SecOpsClient with OAuth credentials adapter",
                    "credentials_info": creds_info
                })
            except Exception as e:
                return jsonify({
                    "success": False,
                    "error": f"Failed to initialize SecOpsClient: {str(e)}",
                    "error_type": type(e).__name__,
                    "credentials_info": {
                        "token_exists": bool(creds_dict.get('token')),
                        "refresh_token_exists": bool(creds_dict.get('refresh_token')),
                        "scopes": creds_dict.get('scopes'),
                        "adapter_created": True
                    }
                }), 500
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "error_type": type(e).__name__
            }), 500

    @app.route('/api/debug/test_chronicle_call', methods=['GET'])
    def debug_test_chronicle_call():
        """
        Debug endpoint to test a simple Chronicle API call.
        This will try to list log types which is a lightweight API call.
        """
        try:
            # Get environment index from query param, default to 0
            env_index = request.args.get('env_index', 0, type=int)
            
            # Get credentials from session
            creds_dict = session.get('credentials')
            if not creds_dict:
                return jsonify({
                    "success": False,
                    "error": "No credentials found in session",
                    "message": "Please login first"
                }), 401
            
            # Check if we have environments configured
            environments = session.get('environments', [])
            if not environments:
                return jsonify({
                    "success": False,
                    "error": "No environments configured",
                    "message": "Please add an environment first"
                }), 400
            
            if not (0 <= env_index < len(environments)):
                return jsonify({
                    "success": False,
                    "error": f"Environment index {env_index} out of range",
                    "message": f"Valid indices are 0-{len(environments)-1}"
                }), 400
            
            # Get environment details
            env = environments[env_index]
            
            # Create OAuth credentials
            from google.auth.transport.requests import Request
            
            oauth_creds = OAuth2Credentials(
                token=creds_dict.get('token'),
                refresh_token=creds_dict.get('refresh_token'),
                token_uri=creds_dict.get('token_uri'),
                client_id=creds_dict.get('client_id'),
                client_secret=creds_dict.get('client_secret'),
                scopes=creds_dict.get('scopes')
            )
            
            # Refresh if needed
            if oauth_creds.expired and oauth_creds.refresh_token:
                oauth_creds.refresh(Request())
                session['credentials'] = credentials_to_dict(oauth_creds)
                
            # Create our adapter with the with_scopes method
            adapter_creds = OAuth2CredentialsAdapter(
                token=oauth_creds.token,
                refresh_token=oauth_creds.refresh_token,
                token_uri=oauth_creds.token_uri,
                client_id=oauth_creds.client_id,
                client_secret=oauth_creds.client_secret,
                scopes=oauth_creds.scopes,
                expiry=oauth_creds.expiry
            )
            
            # Try to initialize SecOpsClient and Chronicle client
            try:
                from secops import SecOpsClient
                
                app.logger.info(f"Initializing SecOpsClient for Chronicle API test")
                secops_client = SecOpsClient(credentials=adapter_creds)
                
                app.logger.info(f"Initializing Chronicle client with customer_id={env['customerId']}, project_id={env['projectId']}, region={env['region']}")
                chronicle_client = secops_client.chronicle(
                    customer_id=env['customerId'],
                    project_id=env['projectId'],
                    region=env['region']
                )
                
                # Make a simple API call
                app.logger.info("Making API call to get log types")
                # Try to get the first few log types (limit to 3 for this test)
                log_types = chronicle_client.get_all_log_types()[:3]
                
                return jsonify({
                    "success": True,
                    "message": "Successfully made Chronicle API call",
                    "data": {
                        "log_types_sample": [
                            {
                                "id": lt.id,
                                "description": lt.description
                            } for lt in log_types
                        ],
                        "environment": {
                            "name": env["name"],
                            "customer_id": env["customerId"],
                            "project_id": env["projectId"],
                            "region": env["region"]
                        }
                    }
                })
            except Exception as e:
                app.logger.error(f"API call failed: {e}", exc_info=True)
                return jsonify({
                    "success": False,
                    "error": f"Chronicle API call failed: {str(e)}",
                    "error_type": type(e).__name__,
                    "environment": {
                        "name": env["name"],
                        "customer_id": env["customerId"],
                        "project_id": env["projectId"],
                        "region": env["region"]
                    }
                }), 500
        except Exception as e:
            app.logger.error(f"Test failed: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": f"Test failed: {str(e)}",
                "error_type": type(e).__name__
            }), 500

@app.route('/api/tools/validate_query', methods=['POST'])
def tool_validate_query():
    """Validate a UDM query syntax."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if data.get('query_to_validate'):
        params['query'] = data['query_to_validate']
    else:
        return jsonify({"success": False, "error": "Missing query parameter", "env_status": "error"}), 400
    
    return _handle_sdk_call("Validate Query", chronicle_client.validate_query, params, data)

@app.route('/api/tools/translate_nl_to_udm', methods=['POST'])
def tool_translate_nl_to_udm():
    """Translate natural language query to UDM query syntax."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if data.get('natural_language_text'):
        params['text'] = data['natural_language_text']
    else:
        return jsonify({"success": False, "error": "Missing natural language text parameter", "env_status": "error"}), 400
    
    # The SDK likely returns just the translated query string, so we'll handle differently than most endpoints
    try:
        _add_to_history("Translate NL to UDM", data)
        translated_query = chronicle_client.translate_nl_to_udm(**params)
        return jsonify({"success": True, "data": {"translated_query": translated_query}, "env_status": "ok"})
    except Exception as e:
        app.logger.error(f"Error in translate_nl_to_udm: {e}")
        return jsonify({"success": False, "error": str(e), "env_status": "error"}), 400

@app.route('/api/tools/rule_create_retrohunt', methods=['POST'])
def tool_rule_create_retrohunt():
    """Create a retrohunt for a rule."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = parse_time_params(data)
    if data.get('rule_id_for_retrohunt'):
        params['rule_id'] = data['rule_id_for_retrohunt']
    else:
        return jsonify({"success": False, "error": "Missing rule ID parameter", "env_status": "error"}), 400
    
    return _handle_sdk_call("Create Retrohunt", chronicle_client.create_retrohunt, params, data)

@app.route('/api/tools/rule_get_retrohunt', methods=['POST'])
def tool_rule_get_retrohunt():
    """Get the status of a retrohunt operation."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if not data.get('rule_id_of_retrohunt'):
        return jsonify({"success": False, "error": "Missing rule ID parameter", "env_status": "error"}), 400
    if not data.get('retrohunt_operation_id'):
        return jsonify({"success": False, "error": "Missing retrohunt operation ID parameter", "env_status": "error"}), 400
    
    params['rule_id'] = data['rule_id_of_retrohunt']
    params['operation_id'] = data['retrohunt_operation_id']
    
    return _handle_sdk_call("Get Retrohunt Status", chronicle_client.get_retrohunt, params, data)

@app.route('/api/tools/rule_list_detections', methods=['POST'])
def tool_rule_list_detections():
    """List detections for a rule."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if not data.get('rule_id_for_detections'):
        return jsonify({"success": False, "error": "Missing rule ID parameter", "env_status": "error"}), 400
    
    params['rule_id'] = data['rule_id_for_detections']
    
    # Optional parameters
    if data.get('alert_state_filter'):
        params['alert_state'] = data['alert_state_filter']
    if data.get('page_size_detections'):
        params['page_size'] = int(data['page_size_detections'])
    if data.get('page_token_detections'):
        params['page_token'] = data['page_token_detections']
    
    return _handle_sdk_call("List Rule Detections", chronicle_client.list_detections, params, data)

@app.route('/api/tools/rule_list_errors', methods=['POST'])
def tool_rule_list_errors():
    """List execution errors for a rule."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if not data.get('rule_id_for_errors'):
        return jsonify({"success": False, "error": "Missing rule ID parameter", "env_status": "error"}), 400
    
    params['rule_id'] = data['rule_id_for_errors']
    
    return _handle_sdk_call("List Rule Errors", chronicle_client.list_errors, params, data)

@app.route('/api/tools/rule_search_alerts', methods=['POST'])
def tool_rule_search_alerts():
    """Search for alerts generated by rules."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = parse_time_params(data)
    
    # Optional parameters
    if data.get('page_size_rule_alerts'):
        params['page_size'] = int(data['page_size_rule_alerts'])
    
    return _handle_sdk_call("Search Rule Alerts", chronicle_client.search_rule_alerts, params, data)

@app.route('/api/tools/rule_set_batch_update', methods=['POST'])
def tool_rule_set_batch_update():
    """Batch update curated rule set deployments."""
    data = request.json
    env_index = data.get('environmentIndex')
    chronicle_client = _get_chronicle_client(env_index)
    
    params = {}
    if not data.get('deployments_json'):
        return jsonify({"success": False, "error": "Missing deployments parameter", "env_status": "error"}), 400
    
    try:
        # Parse deployments JSON
        if isinstance(data['deployments_json'], str):
            params['deployments'] = json.loads(data['deployments_json'])
        else:
            params['deployments'] = data['deployments_json']
        
        return _handle_sdk_call("Batch Update Rule Sets", chronicle_client.batch_update_curated_rule_set_deployments, params, data)
    except json.JSONDecodeError:
        return jsonify({"success": False, "error": "Invalid JSON for deployments", "env_status": "error"}), 400

# Register debug endpoints only in debug mode
debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
if debug_mode:
    app.logger.warning("Debug mode is enabled - registering debug endpoints")
    register_debug_endpoints(app)
else:
    app.logger.info("Running in production mode - debug endpoints are disabled")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    
    # For local development without App Engine context (e.g. running directly with python app.py)
    # ensure HTTPS if not debug, as OAuth typically requires it.
    # However, google-auth-oauthlib handles http for localhost for redirect_uri if OAUTHLIB_INSECURE_TRANSPORT is set.
    if debug_mode:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        # Production execution (e.g. via Gunicorn as in app.yaml)
        # Gunicorn or App Engine's frontend will handle SSL.
        app.run(host='0.0.0.0', port=port) # Gunicorn will bind to this