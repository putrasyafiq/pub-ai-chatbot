import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from vertexai.preview.generative_models import GenerativeModel, Part, Content, ChatSession

# Configure Flask app
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Configure Vertex AI
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION")

if not PROJECT_ID or not LOCATION:
    raise ValueError("Please set GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION environment variables.")

# Define the directory for storing session files
SESSIONS_DIR = "sessions"
os.makedirs(SESSIONS_DIR, exist_ok=True) # Create the directory if it doesn't exist

def get_session_file_path(session_id: str) -> str:
    """Returns the file path for a given session ID."""
    return os.path.join(SESSIONS_DIR, f"{session_id}.json")

def load_session_data(session_id: str) -> dict:
    """Loads session data (name and history) from a JSON file."""
    file_path = get_session_file_path(session_id)
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Reconstruct Content objects for history from the loaded raw data
        history = []
        if 'history' in data and data['history']:
            for item in data['history']:
                parts = [Part.from_text(p) for p in item['parts']]
                history.append(Content(role=item['role'], parts=parts))
        
        return {'name': data.get('name'), 'history': history}
    return {'name': None, 'history': []} # Return empty if file not found

def save_session_data(session_id: str, name: str, history: list[Content]):
    """Saves session data (name and history) to a JSON file."""
    file_path = get_session_file_path(session_id)
    
    # Convert Content objects to a serializable format
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

@app.route('/chat-vertex', methods=['POST'])
def chat_with_vertex():
    """Handles chat requests and interacts with the Vertex AI model."""
    try:
        data = request.get_json()
        session_id = data.get('sessionId')
        user_message = data.get('message')
        system_instructions = data.get('instructions', '')
        session_name = data.get('sessionName') # Get session name from frontend

        if not session_id or not user_message:
            return jsonify({'error': 'Missing sessionId or message'}), 400

        # Load existing session data
        session_data = load_session_data(session_id)
        history = session_data['history']
        # If a name is passed from the frontend (e.g., initial message for a new session), update it
        # Otherwise, keep the existing name from the loaded session_data
        current_session_name = session_name if session_name is not None else session_data['name']

        # Initialize the model and start a chat session with the loaded history
        model = GenerativeModel("gemini-2.5-flash-lite")
        chat_session = model.start_chat(history=history)

        # Prepare the current user's message including system instructions if provided
        user_content_parts = []
        if system_instructions:
            user_content_parts.append(Part.from_text(f"System instructions: {system_instructions}"))
        user_content_parts.append(Part.from_text(user_message))

        # Send message to the Vertex AI model
        response_from_model = chat_session.send_message(user_content_parts)

        # Extract the text content from the response
        vertex_response_text = response_from_model.text

        # Save the *entire* updated history (and current name) back to the session file.
        save_session_data(session_id, current_session_name, chat_session.history)

        return jsonify({'response': vertex_response_text})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': f'An internal server error occurred: {e}'}), 500


@app.route('/sessions', methods=['GET'])
def list_sessions():
    """Lists all available session IDs and names."""
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
        # Sort by name if available, otherwise by ID
        session_data_list.sort(key=lambda x: x['name'] if x['name'] else x['id'])
        return jsonify(session_data_list)
    except Exception as e:
        print(f"Error listing sessions: {e}")
        return jsonify({'error': 'Could not retrieve session list'}), 500

@app.route('/sessions/<session_id>', methods=['GET'])
def get_session_history(session_id):
    """Retrieves the history for a specific session ID."""
    try:
        session_data = load_session_data(session_id)
        history = session_data['history']
        
        # Convert Content objects back to a simple serializable format for the frontend
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
    """Renames a specific session."""
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
    """Deletes a specific session."""
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

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)