import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os

# Constants
MASTER_PASSWORD = "admin123"
DATA_FILE = "stored_data.json"

# Generate or load encryption key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

with open("secret.key", "rb") as key_file:
    KEY = key_file.read()

cipher = Fernet(KEY)

# Load stored data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Session state for failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    if encrypted_text in stored_data and stored_data[encrypted_text]["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# Streamlit UI
st.markdown(
    """
    <style>
    .stApp {
        font-family: 'Segoe UI', sans-serif;
    }
    .title-style {
        font-size: 40px;
        color: #4B9CD3;
        text-align: center;
        font-weight: 700;
        margin-bottom: 2rem;
    }
    .subheader-style {
        font-size: 24px;
        color: #f0f0f0;
        font-weight: 600;
        margin-top: 2rem;
    }
    .input-style {
        margin-bottom: 1rem;
    }
    .button-style {
        margin-top: 1rem;
    }
    .error-style {
        color: #e74c3c;
        font-weight: 600;
    }
    .success-style {
        color: #2ecc71;
        font-weight: 600;
    }
    .login-input {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        padding: 0.75rem;
        border-radius: 5px;
    }
    .login-btn {
        background-color: #4B9CD3;
        color: white;
        padding: 0.75rem;
        border-radius: 5px;
        cursor: pointer;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown("<div class='title-style'>🔒 Secure Data Encryption System</div>", unsafe_allow_html=True)

# Sidebar Menu
menu = ["🏠 Home", "📥 Store Data", "🔓 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("🔍 Navigate", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:", key="user_data", className="input-style")
    passkey = st.text_input("Enter Passkey:", type="password", key="passkey", className="input-style")

    if st.button("Encrypt & Save", key="store_button", className="button-style"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_data()
            st.success("✅ Data stored securely!", icon="✅", className="success-style")
        else:
            st.error("⚠️ Both fields are required!", icon="❌", className="error-style")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:", key="encrypted_data", className="input-style")
    passkey = st.text_input("Enter Passkey:", type="password", key="passkey_input", className="input-style")

    if st.button("Decrypt", key="decrypt_button", className="button-style"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}", icon="✅", className="success-style")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}", className="error-style")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!", icon="❌", className="error-style")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password", key="login_pass", className="login-input")

    if st.button("Login", key="login_button", className="login-btn"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!", icon="❌", className="error-style")
