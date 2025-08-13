import os
import json
import shutil
from flask import Flask, request, jsonify, send_file, redirect, url_for, session
from flask_cors import CORS
from vertexai.preview.generative_models import GenerativeModel, Part, Content, ChatSession

# Google OAuth imports
import google.oauth2.credentials
import google.auth.transport.requests
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token

# Configure Flask app
app = Flask(__name__, template_folder='templates')
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

# Insecure transport for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Configure Vertex AI
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION")

if not PROJECT_ID or not LOCATION:
    print("WARNING: GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION environment variables not set.")

# Define the root directory for all user data
USERS_DATA_DIR = "users_data"
os.makedirs(USERS_DATA_DIR, exist_ok=True)

# --- Helper Functions for File System Management ---

def get_user_data_dir() -> str | None:
    """Returns the user-specific directory path based on the logged-in user's email."""
    if 'email' not in session:
        return None
    
    user_email_hash = str(hash(session['email']))
    user_dir = os.path.join(USERS_DATA_DIR, user_email_hash)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def get_bots_dir() -> str | None:
    """Returns the bots directory for the logged-in user."""
    user_dir = get_user_data_dir()
    if not user_dir:
        return None
    bots_dir = os.path.join(user_dir, "bots")
    os.makedirs(bots_dir, exist_ok=True)
    return bots_dir

def get_bot_dir(bot_id: str) -> str | None:
    """Returns the directory for a specific bot."""
    bots_dir = get_bots_dir()
    if not bots_dir:
        return None
    bot_dir = os.path.join(bots_dir, bot_id)
    return bot_dir

def get_bot_info_path(bot_id: str) -> str | None:
    """Returns the file path for a bot's info file."""
    bot_dir = get_bot_dir(bot_id)
    if not bot_dir:
        return None
    return os.path.join(bot_dir, "info.json")

def get_session_dir(bot_id: str) -> str | None:
    """Returns the sessions directory for a specific bot."""
    bot_dir = get_bot_dir(bot_id)
    if not bot_dir:
        return None
    sessions_dir = os.path.join(bot_dir, "sessions")
    os.makedirs(sessions_dir, exist_ok=True)
    return sessions_dir

def get_session_file_path(bot_id: str, session_id: str) -> str | None:
    """Returns the file path for a given session ID within a bot's directory."""
    session_dir = get_session_dir(bot_id)
    if not session_dir:
        return None
    return os.path.join(session_dir, f"{session_id}.json")

# --- Bot and Session Data Loading/Saving Functions ---

def load_bot_info(bot_id: str) -> dict | None:
    """Loads a bot's info (name, instructions, permissions) from a JSON file."""
    file_path = get_bot_info_path(bot_id)
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def save_bot_info(bot_id: str, info_data: dict):
    """Saves a bot's info to a JSON file."""
    file_path = get_bot_info_path(bot_id)
    if not file_path:
        return
    bot_dir = get_bot_dir(bot_id)
    os.makedirs(bot_dir, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(info_data, f, indent=4)

def load_session_data(bot_id: str, session_id: str) -> dict:
    """Loads session data (name and history) from a JSON file."""
    file_path = get_session_file_path(bot_id, session_id)
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        history = []
        if 'history' in data and data['history']:
            for item in data['history']:
                parts = [Part.from_text(p) for p in item['parts']]
                history.append(Content(role=item['role'], parts=parts))
        
        return {'name': data.get('name'), 'history': history}
    return {'name': None, 'history': []}

def save_session_data(bot_id: str, session_id: str, name: str, history: list[Content]):
    """Saves session data (name and history) to a JSON file."""
    file_path = get_session_file_path(bot_id, session_id)
    if not file_path:
        return
    
    serializable_history = []
    for content_item in history:
        serializable_parts = [p.text for p in content_item.parts if hasattr(p, 'text')]
        serializable_history.append({'role': content_item.role, 'parts': serializable_parts})
    
    session_data = {
        'name': name,
        'history': serializable_history
    }

    session_dir = get_session_dir(bot_id)
    if not session_dir:
        return
    os.makedirs(session_dir, exist_ok=True)

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(session_data, f, indent=4)

# --- Access Control Logic ---
def check_bot_access(bot_id: str):
    bot_info = load_bot_info(bot_id)
    if not bot_info:
        return False, "Bot not found."
    
    owner_email = bot_info.get('owner_email')
    user_email = session.get('email')

    # The owner always has access
    if user_email and user_email == owner_email:
        return True, None

    # Check permissions for other users
    permissions = bot_info.get('permissions', 'restricted')
    allowed_users = bot_info.get('allowed_users', [])
    allowed_domains = bot_info.get('allowed_domains', [])

    if permissions == 'anyone':
        return True, None

    if permissions == 'domain':
        if not user_email:
            return False, "Authentication required for this bot."
        user_domain = user_email.split('@')[-1]
        if user_domain in allowed_domains:
            return True, None
    
    if permissions == 'restricted':
        if not user_email:
            return False, "Authentication required for this bot."
        if user_email in allowed_users:
            return True, None

    return False, "You do not have permission to access this bot."

# --- Google OAuth Routes ---

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
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
        print(f"Error during OAuth callback: {e}")
        return redirect(url_for('serve_index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('serve_index'))

# --- Core App Routes ---

@app.route('/')
def serve_index():
    session['is_public_view'] = False
    return send_file('templates/index.html')

@app.route('/bot/<bot_id>')
def serve_bot(bot_id):
    is_owner = 'email' in session and load_bot_info(bot_id) and load_bot_info(bot_id).get('owner_email') == session.get('email')
    
    # We allow the owner to always load the page, even if permissions are broken
    if not is_owner:
        has_access, message = check_bot_access(bot_id)
        if not has_access:
            # For non-owners, redirect to index with an error message
            session['error_message'] = message
            return redirect(url_for('serve_index'))
    
    session['is_public_view'] = True
    return send_file('templates/index.html')

@app.route('/user_info', methods=['GET'])
def get_user_info():
    if 'email' in session:
        return jsonify({
            'email': session['email'],
            'name': session['name'],
            'logged_in': True,
            'is_public_view': session.get('is_public_view', False)
        })
    return jsonify({
        'logged_in': False,
        'is_public_view': session.get('is_public_view', False)
    })

@app.route('/chat-vertex', methods=['POST'])
def chat_with_vertex():
    try:
        data = request.get_json()
        bot_id = data.get('botId')
        session_id = data.get('sessionId')
        user_message = data.get('message')
        session_name = data.get('sessionName')

        if not bot_id or not session_id or not user_message:
            return jsonify({'error': 'Missing botId, sessionId, or message'}), 400

        has_access, message = check_bot_access(bot_id)
        if not has_access:
            return jsonify({'error': message}), 403

        # Load bot-specific system instructions
        bot_info = load_bot_info(bot_id)
        system_instructions = bot_info.get('system_instructions', '')

        session_data = load_session_data(bot_id, session_id)
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
        save_session_data(bot_id, session_id, current_session_name, chat_session.history)

        return jsonify({'response': vertex_response_text})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': f'An internal server error occurred: {e}'}), 500

# --- Bot Management Routes ---

@app.route('/bots', methods=['GET'])
def list_bots():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        bots_dir = get_bots_dir()
        if not bots_dir or not os.path.exists(bots_dir):
            return jsonify([])

        bot_list = []
        for bot_id in os.listdir(bots_dir):
            bot_info = load_bot_info(bot_id)
            if bot_info:
                bot_list.append({
                    'id': bot_id,
                    'name': bot_info.get('name', 'Untitled Bot'),
                    'permissions': bot_info.get('permissions', 'restricted')
                })
        bot_list.sort(key=lambda x: x['name'])
        return jsonify(bot_list)
    except Exception as e:
        print(f"Error listing bots: {e}")
        return jsonify({'error': 'Could not retrieve bot list'}), 500

@app.route('/bots', methods=['POST'])
def create_bot():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    try:
        data = request.get_json()
        bot_id = os.urandom(8).hex()
        bot_name = data.get('name', 'New Bot')
        
        new_bot_info = {
            'name': bot_name,
            'owner_email': session['email'],
            'system_instructions': '',
            'permissions': 'restricted',
            'allowed_users': [],
            'allowed_domains': []
        }
        save_bot_info(bot_id, new_bot_info)
        return jsonify({'message': 'Bot created successfully', 'botId': bot_id})
    except Exception as e:
        print(f"Error creating bot: {e}")
        return jsonify({'error': 'Could not create bot'}), 500

@app.route('/bots/rename/<bot_id>', methods=['POST'])
def rename_bot(bot_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    
    bot_info = load_bot_info(bot_id)
    if not bot_info or bot_info.get('owner_email') != session['email']:
        return jsonify({'error': 'Bot not found or you do not have permission to edit'}), 403

    try:
        data = request.get_json()
        new_name = data.get('newName')
        if not new_name:
            return jsonify({'error': 'New name not provided'}), 400
        
        bot_info['name'] = new_name
        save_bot_info(bot_id, bot_info)
        return jsonify({'message': 'Bot renamed successfully'})
    except Exception as e:
        print(f"Error renaming bot {bot_id}: {e}")
        return jsonify({'error': 'Could not rename bot'}), 500

@app.route('/bots/delete/<bot_id>', methods=['DELETE'])
def delete_bot(bot_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    
    bot_info = load_bot_info(bot_id)
    if not bot_info or bot_info.get('owner_email') != session['email']:
        return jsonify({'error': 'Bot not found or you do not have permission to delete'}), 403

    try:
        bot_dir = get_bot_dir(bot_id)
        if bot_dir and os.path.exists(bot_dir):
            shutil.rmtree(bot_dir)
            return jsonify({'message': 'Bot deleted successfully'})
        else:
            return jsonify({'error': 'Bot not found'}), 404
    except Exception as e:
        print(f"Error deleting bot {bot_id}: {e}")
        return jsonify({'error': 'Could not delete bot'}), 500

@app.route('/bots/<bot_id>', methods=['GET'])
def get_bot(bot_id):
    has_access, message = check_bot_access(bot_id)
    if not has_access:
        return jsonify({'error': message}), 403

    try:
        bot_info = load_bot_info(bot_id)
        if not bot_info:
            return jsonify({'error': 'Bot not found'}), 404

        sessions_dir = get_session_dir(bot_id)
        session_list = []
        if os.path.exists(sessions_dir):
            for f in os.listdir(sessions_dir):
                if f.endswith('.json'):
                    session_id = os.path.splitext(f)[0]
                    session_info = load_session_data(bot_id, session_id)
                    session_list.append({
                        'id': session_id,
                        'name': session_info.get('name', 'Untitled Session')
                    })
        session_list.sort(key=lambda x: x['name'])
        
        # Only return sensitive data like owner_email to the owner
        is_owner = 'email' in session and bot_info['owner_email'] == session['email']
        if not is_owner:
            bot_info.pop('owner_email', None)
            bot_info.pop('allowed_users', None)
            bot_info.pop('allowed_domains', None)
        
        return jsonify({
            'bot': bot_info,
            'sessions': session_list,
            'is_owner': is_owner
        })
    except FileNotFoundError:
        return jsonify({'error': 'Bot not found'}), 404
    except Exception as e:
        print(f"Error fetching bot {bot_id}: {e}")
        return jsonify({'error': 'Could not retrieve bot info and sessions'}), 500

@app.route('/bots/permissions/<bot_id>', methods=['POST'])
def update_bot_permissions(bot_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    
    bot_info = load_bot_info(bot_id)
    if not bot_info or bot_info.get('owner_email') != session['email']:
        return jsonify({'error': 'Bot not found or you do not have permission to edit'}), 403
    
    try:
        data = request.get_json()
        bot_info['permissions'] = data.get('permissions', bot_info['permissions'])
        bot_info['allowed_users'] = data.get('allowed_users', bot_info['allowed_users'])
        bot_info['allowed_domains'] = data.get('allowed_domains', bot_info['allowed_domains'])

        save_bot_info(bot_id, bot_info)
        return jsonify({'message': 'Permissions updated successfully'})
    except Exception as e:
        print(f"Error updating permissions for bot {bot_id}: {e}")
        return jsonify({'error': 'Could not update permissions'}), 500

# --- Session Management Routes ---

@app.route('/bots/<bot_id>/sessions/new', methods=['POST'])
def create_session(bot_id):
    is_owner = 'email' in session and load_bot_info(bot_id) and load_bot_info(bot_id).get('owner_email') == session.get('email')

    if not is_owner:
        bot_info = load_bot_info(bot_id)
        if not bot_info:
            return jsonify({'error': 'Bot not found'}), 404
        if bot_info['permissions'] == 'restricted':
            return jsonify({'error': 'Restricted bot. Sessions cannot be created anonymously.'}), 403
        if bot_info['permissions'] == 'domain':
            if not session.get('email'):
                return jsonify({'error': 'Login required for this bot.'}), 401
            user_domain = session['email'].split('@')[-1]
            if user_domain not in bot_info.get('allowed_domains', []):
                return jsonify({'error': 'Domain not allowed for this bot.'}), 403

    try:
        session_id = os.urandom(8).hex()
        save_session_data(bot_id, session_id, "New Session", [])
        return jsonify({'message': 'Session created successfully', 'sessionId': session_id})
    except Exception as e:
        print(f"Error creating session for bot {bot_id}: {e}")
        return jsonify({'error': 'Could not create new session'}), 500

@app.route('/bots/<bot_id>/sessions/<session_id>', methods=['GET'])
def get_session_history(bot_id, session_id):
    has_access, message = check_bot_access(bot_id)
    if not has_access:
        return jsonify({'error': message}), 403

    try:
        session_data = load_session_data(bot_id, session_id)
        if not session_data:
            return jsonify({'error': 'Session not found'}), 404
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

@app.route('/bots/<bot_id>/sessions/rename/<session_id>', methods=['POST'])
def rename_session(bot_id, session_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    
    bot_info = load_bot_info(bot_id)
    if not bot_info or bot_info.get('owner_email') != session['email']:
        return jsonify({'error': 'Bot not found or you do not have permission to rename sessions'}), 403

    try:
        data = request.get_json()
        new_name = data.get('newName')
        if not new_name:
            return jsonify({'error': 'New name not provided'}), 400
        
        session_data = load_session_data(bot_id, session_id)
        if not session_data:
            return jsonify({'error': 'Session not found'}), 404
        
        save_session_data(bot_id, session_id, new_name, session_data['history'])
        return jsonify({'message': 'Session renamed successfully'})
    except Exception as e:
        print(f"Error renaming session {session_id}: {e}")
        return jsonify({'error': 'Could not rename session'}), 500

@app.route('/bots/<bot_id>/sessions/delete/<session_id>', methods=['DELETE'])
def delete_session(bot_id, session_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    
    bot_info = load_bot_info(bot_id)
    if not bot_info or bot_info.get('owner_email') != session['email']:
        return jsonify({'error': 'Bot not found or you do not have permission to delete sessions'}), 403
        
    try:
        file_path = get_session_file_path(bot_id, session_id)
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({'message': 'Session deleted successfully'})
        else:
            return jsonify({'error': 'Session not found'}), 404
    except Exception as e:
        print(f"Error deleting session {session_id}: {e}")
        return jsonify({'error': 'Could not delete session'}), 500

# --- Bot Settings Routes ---

@app.route('/bots/<bot_id>/settings', methods=['GET'])
def get_bot_settings(bot_id):
    has_access, message = check_bot_access(bot_id)
    if not has_access:
        return jsonify({'error': message}), 403
    
    try:
        bot_info = load_bot_info(bot_id)
        if not bot_info:
            return jsonify({'error': 'Bot not found'}), 404
        
        is_owner = 'email' in session and bot_info['owner_email'] == session['email']
        
        return jsonify({
            'name': bot_info.get('name'),
            'system_instructions': bot_info.get('system_instructions'),
            'permissions': bot_info.get('permissions'),
            'allowed_users': bot_info.get('allowed_users'),
            'allowed_domains': bot_info.get('allowed_domains'),
            'is_owner': is_owner,
            'owner_email': bot_info.get('owner_email')
        })
    except Exception as e:
        print(f"Error retrieving bot settings for {bot_id}: {e}")
        return jsonify({'error': 'Could not retrieve bot settings'}), 500

@app.route('/bots/<bot_id>/settings', methods=['POST'])
def update_bot_settings(bot_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    
    bot_info = load_bot_info(bot_id)
    if not bot_info or bot_info.get('owner_email') != session['email']:
        return jsonify({'error': 'Bot not found or you do not have permission to edit'}), 403
        
    try:
        data = request.get_json()
        new_instructions = data.get('system_instructions', '')
        bot_info['system_instructions'] = new_instructions
        save_bot_info(bot_id, bot_info)
        return jsonify({'message': 'Settings updated successfully'})
    except Exception as e:
        print(f"Error updating settings for {bot_id}: {e}")
        return jsonify({'error': 'Could not update settings'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)