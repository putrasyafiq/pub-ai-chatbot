import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from vertexai.preview.generative_models import GenerativeModel, Part, ChatSession

# Configure Flask app
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Initialize the Vertex AI model
# Make sure to replace 'your-project-id' and 'your-location'
# For example, project='my-cool-project', location='us-central1'
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION")

if not PROJECT_ID or not LOCATION:
    raise ValueError("Please set GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION environment variables.")

# This is where we will store the chat history for a session.
# In a real-world application, this would be per-user and stored in a database.
chat_sessions = {}

def get_chat_session(session_id: str) -> ChatSession:
    """Retrieves or creates a chat session for a given ID."""
    if session_id not in chat_sessions:
        # Initialize the model and a new chat session with history
        model = GenerativeModel("gemini-2.5-flash-lite")
        chat_sessions[session_id] = model.start_chat()
    return chat_sessions[session_id]

@app.route('/chat-vertex', methods=['POST'])
def chat_with_vertex():
    """Handles chat requests and interacts with the Vertex AI model."""
    try:
        data = request.get_json()
        user_message = data.get('message')
        system_instructions = data.get('instructions', '')
        
        # In a real application, you'd get a session_id from the user's cookie or session.
        # For this example, we'll use a hardcoded ID for simplicity.
        session_id = "default-user" 
        chat_session = get_chat_session(session_id)

        if not user_message:
            return jsonify({'error': 'No message provided'}), 400

        # Combine system instructions with the user's message for each turn
        # This is passed as 'context' to the model.
        full_message_parts = [Part.from_text(f"System instructions: {system_instructions}"),
                              Part.from_text(f"User: {user_message}")] if system_instructions else [Part.from_text(user_message)]

        # Send message to the Vertex AI model
        response = chat_session.send_message(full_message_parts)

        # Extract the text content from the response
        vertex_response = response.text

        return jsonify({'response': vertex_response})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': 'An internal server error occurred'}), 500

if __name__ == '__main__':
    # You can change the host and port if needed
    app.run(debug=True, host='127.0.0.1', port=5000)