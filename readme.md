# AI Chatbot Generator 🤖

Welcome to the AI Chatbot Generator! This application allows you to **create, customize, and manage your own AI chatbots**. You can define their personalities through system instructions, chat with them, and even share them with others.

## ✨ Features

* **Custom Chatbot Creation:** Easily create new AI chatbots tailored to your needs.

* **Personalized System Instructions:** Define how your bot should behave and respond using custom system instructions.

* **Session Management:** Keep track of your conversations with different sessions for each bot.

* **Google Authentication:** Securely log in and manage your bots using your Google account.

* **Bot Sharing:** Share your bots with specific users, domains, or make them publicly accessible via a unique link.

* **Intuitive User Interface:** A clean and responsive design built with Tailwind CSS for a seamless experience.

## 🚀 Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

Before you begin, ensure you have the following installed:

* **Python 3.8+**

* **`pip`** (Python package installer)

* **Google Cloud Project** with **Vertex AI API enabled**

* **Google OAuth 2.0 Client ID** and **Client Secret** (downloaded as `keys.json`)

### Installation

1.  **Clone the repository:**

    ```
    git clone [https://github.com/putrasyafiq/pub-ai-chatbot.git](https://github.com/putrasyafiq/pub-ai-chatbot.git)
    cd your-repo-name
    ```

2.  **Set up a virtual environment** (recommended):

    ```
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required Python packages:**

    ```
    pip install -r requirements.txt
    ```

    (You'll need to create a `requirements.txt` file if you don't have one, containing `Flask`, `flask-cors`, `google-auth-oauthlib`, `google-auth`, `vertexai`)

4.  **Configure Environment Variables:**
    Create a `.env` file in the root directory or set these directly in your environment:

    ```
    FLASK_SECRET_KEY="your_super_secret_key_here" # Change this to a strong, random key
    GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
    GOOGLE_CLOUD_LOCATION="us-central1" # Or your preferred Vertex AI region
    ```

5.  **Place your `keys.json` file** (Google OAuth client secrets) in the root directory of the project.

### Running the Application

1.  **Start the Flask server:**

    ```
    python app.py
    ```

2.  **Open your web browser** and navigate to `http://127.0.0.1:5000/`.

## 📖 Usage

1.  **Log In with Google:** Click the "Log In with Google" button to authenticate and access your private bots.

2.  **Create a New Bot:** Once logged in, click "+ New Bot" to create your first chatbot.

3.  **Customize Instructions:** Select a bot from "My Bots" and modify its system instructions in the textarea. Click "Save Instructions" to update.

4.  **Start a Session:** Click "+ New Session" to begin a new conversation with your selected bot.

5.  **Chat:** Type your messages in the input field and press Enter or click the send button.

6.  **Manage Bots & Sessions:** Use the rename and delete icons next to each bot and session to organize your chat experience.

7.  **Share Your Bots:** Click the share icon next to a bot to generate a shareable link and manage permissions (restricted, by domain, or anyone with the link).

## 🏗️ Project Structure

```
.
├── app.py                  # Flask backend for API endpoints and chatbot logic
├── templates/
│   └── index.html          # Frontend HTML, CSS (Tailwind), and JavaScript
├── keys.json               # Google OAuth client secrets (replace with your own)
├── users_data/             # Stores user, bot, and session data (created on first run)
│   ├── users_info/         # User-specific metadata
│   └── {google_id}/        # Directory for each user's bots
│       └── bots/
│           └── {bot_id}/   # Directory for each bot
│               ├── info.json       # Bot name, system instructions, permissions
│               └── sessions/
│                   └── {session_id}.json # Chat history for each session
└── README.md               # This file
```

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, please open an issue or submit a pull request.

## 📞 Contact

If you have any questions, feel free to reach out at [putrasyafiqbr@gmail.com] or open an issue on GitHub.
