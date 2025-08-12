import os
import json
from flask import Flask, request, jsonify, send_file, redirect, url_for, session
from flask_cors import CORS
from vertexai.preview.generative_models import GenerativeModel, Part, Content, ChatSession

# Google OAuth imports
import google.oauth2.credentials
import google.auth.transport.requests
from google_auth_oauthlib.flow import Flow

from google.oauth2 import id_token

# Configure Flask app
app = Flask(__name__, template_folder='templates') # Specify templates folder
# A secret key is required for sessions.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "your_secret_key_here")
CORS(app, supports_credentials=True)

# Google OAuth 2.0 configuration
CLIENT_SECRETS_FILE = "keys.json"
SCOPES = ["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile", "openid"]

# Set up the OAuth flow
flow = Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE, scopes=SCOPES,
    redirect_uri='http://127.0.0.1:5000/oauth2callback'
)

# Configure Vertex AI
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION")

if not PROJECT_ID or not LOCATION:
    print("WARNING: GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION environment variables not set.")

# Define the directory for storing session files and settings
SESSIONS_DIR = "sessions"
SETTINGS_FILE = "settings.json"
os.makedirs(SESSIONS_DIR, exist_ok=True)


def get_session_file_path(session_id: str) -> str:
    """Returns the file path for a given session ID."""
    return os.path.join(SESSIONS_DIR, f"{session_id}.json")

def load_session_data(session_id: str) -> dict:
    """Loads session data (name and history) from a JSON file."""
    file_path = get_session_file_path(session_id)
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        history = []
        if 'history' in data and data['history']:
            for item in data['history']:
                parts = [Part.from_text(p) for p in item['parts']]
                history.append(Content(role=item['role'], parts=parts))
        
        return {'name': data.get('name'), 'history': history}
    return {'name': None, 'history': []}

def save_session_data(session_id: str, name: str, history: list[Content]):
    """Saves session data (name and history) to a JSON file."""
    file_path = get_session_file_path(session_id)
    
    serializable_history = []
    for content_item in history:
        serializable_parts = [p.text for p in content_item.parts if hasattr(p, 'text')]
        serializable_history.append({'role': content_item.role, 'parts': serializable_parts})
    
    session_data = {
        'name': name,
        'history': serializable_history
    }

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(session_data, f, indent=4)

def load_settings() -> dict:
    """Loads settings from a JSON file."""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'system_instructions': ''}

def save_settings(settings_data: dict):
    """Saves settings to a JSON file."""
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings_data, f, indent=4)

# New routes for Google OAuth
@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    try:
        # State is a security measure to prevent CSRF attacks.
        state = session['state']

        # Fetch the token using the authorization response from Google.
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        # Use id_token.verify_oauth2_token to decode and validate the token
        # It takes the ID token string, the request object, and the client ID.
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            google.auth.transport.requests.Request(),
            flow.client_config['client_id']
        )

        user_email = id_info.get('email')
        user_name = id_info.get('name')

        session['google_id'] = id_info.get('sub')
        session['name'] = user_name
        session['email'] = user_email

        return redirect(url_for('serve_index'))

    except Exception as e:
        # Handle any errors during the token exchange or verification process.
        print(f"Error during OAuth callback: {e}")
        return redirect(url_for('serve_index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('serve_index'))

# Route to get current user info
@app.route('/user_info', methods=['GET'])
def get_user_info():
    if 'email' in session:
        return jsonify({
            'email': session['email'],
            'name': session['name'],
            'logged_in': True
        })
    return jsonify({'logged_in': False})

@app.route('/')
def serve_index():
    """Serves the index.html file from the templates directory."""
    return send_file('templates/index.html')

@app.route('/chat-vertex', methods=['POST'])
def chat_with_vertex():
    # Enforce login for this endpoint
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401

    try:
        data = request.get_json()
        session_id = data.get('sessionId')
        user_message = data.get('message')
        session_name = data.get('sessionName')

        if not session_id or not user_message:
            return jsonify({'error': 'Missing sessionId or message'}), 400

        settings = load_settings()
        system_instructions = settings.get('system_instructions', '')

        session_data = load_session_data(session_id)
        history = session_data['history']
        current_session_name = session_name if session_name is not None else session_data['name']

        model = GenerativeModel("gemini-2.5-flash-lite")
        chat_session = model.start_chat(history=history)

        user_content_parts = []
        if system_instructions:
            user_content_parts.append(Part.from_text(f"System instructions: {system_instructions}"))
        user_content_parts.append(Part.from_text(user_message))

        response_from_model = chat_session.send_message(user_content_parts)
        vertex_response_text = response_from_model.text
        save_session_data(session_id, current_session_name, chat_session.history)

        return jsonify({'response': vertex_response_text})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': f'An internal server error occurred: {e}'}), 500

@app.route('/sessions', methods=['GET'])
def list_sessions():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        session_data_list = []
        for f in os.listdir(SESSIONS_DIR):
            if f.endswith('.json'):
                session_id = os.path.splitext(f)[0]
                session_info = load_session_data(session_id)
                session_data_list.append({
                    'id': session_id,
                    'name': session_info['name']
                })
        session_data_list.sort(key=lambda x: x['name'] if x['name'] else x['id'])
        return jsonify(session_data_list)
    except Exception as e:
        print(f"Error listing sessions: {e}")
        return jsonify({'error': 'Could not retrieve session list'}), 500

@app.route('/sessions/<session_id>', methods=['GET'])
def get_session_history(session_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        session_data = load_session_data(session_id)
        history = session_data['history']
        
        serializable_history = []
        for item in history:
            combined_parts_text = " ".join([p.text for p in item.parts if hasattr(p, 'text')])
            serializable_history.append({'role': item.role, 'parts': [combined_parts_text]})
        
        return jsonify({'name': session_data['name'], 'history': serializable_history})
    except FileNotFoundError:
        return jsonify({'error': 'Session not found'}), 404
    except Exception as e:
        print(f"Error fetching session history for {session_id}: {e}")
        return jsonify({'error': 'Could not retrieve session history'}), 500

@app.route('/sessions/rename/<session_id>', methods=['POST'])
def rename_session(session_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        data = request.get_json()
        new_name = data.get('newName')
        if not new_name:
            return jsonify({'error': 'New name not provided'}), 400
        
        session_data = load_session_data(session_id)
        if not session_data:
            return jsonify({'error': 'Session not found'}), 404
        
        save_session_data(session_id, new_name, session_data['history'])
        return jsonify({'message': 'Session renamed successfully'})
    except Exception as e:
        print(f"Error renaming session {session_id}: {e}")
        return jsonify({'error': 'Could not rename session'}), 500

@app.route('/sessions/delete/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        file_path = get_session_file_path(session_id)
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({'message': 'Session deleted successfully'})
        else:
            return jsonify({'error': 'Session not found'}), 404
    except Exception as e:
        print(f"Error deleting session {session_id}: {e}")
        return jsonify({'error': 'Could not delete session'}), 500

@app.route('/settings', methods=['GET'])
def get_settings():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        settings = load_settings()
        return jsonify(settings)
    except Exception as e:
        print(f"Error retrieving settings: {e}")
        return jsonify({'error': 'Could not retrieve settings'}), 500

@app.route('/settings', methods=['POST'])
def update_settings():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        data = request.get_json()
        new_instructions = data.get('system_instructions', '')
        settings = load_settings()
        settings['system_instructions'] = new_instructions
        save_settings(settings)
        return jsonify({'message': 'Settings updated successfully'})
    except Exception as e:
        print(f"Error updating settings: {e}")
        return jsonify({'error': 'Could not update settings'}), 500

import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)