import streamlit as st
import hashlib
from cryptography.fernet import Fernet

if "users" not in st.session_state:
    st.session_state.users = {}
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, username):
    user_data = st.session_state.stored_data.get(username)
    if not user_data:
        return None
    if user_data["encrypted_text"] == encrypted_text and user_data["passkey"] == hash_text(passkey):
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

def login_ui():
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in st.session_state.users:
            if st.session_state.users[username] == hash_text(password):
                st.session_state.current_user = username
                st.session_state.failed_attempts = 0
                st.session_state.login_successful = True
                st.rerun()
            else:
                st.error("❌ Incorrect password.")
        else:
            st.error("❌ User not found.")

if 'login_successful' in st.session_state and st.session_state.login_successful:
    st.success(f"✅ Welcome back, {st.session_state.current_user}!")
    st.session_state.login_successful = False

def register_ui():
    st.subheader("📝 Register New Account")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    if st.button("Register"):
        if username in st.session_state.users:
            st.warning("⚠️ Username already exists.")
        elif username and password:
            st.session_state.users[username] = hash_text(password)
            st.success("✅ Registered successfully.")
        else:
            st.error("⚠️ All fields required.")

st.title("🔒 Secure Data Encryption System")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "📂 Store Data", "🔍 Retrieve Data", "🚪 Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "🏠 Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "📝 Register":
    register_ui()

elif choice == "🔑 Login":
    login_ui()

elif choice == "🚪 Logout":
    st.session_state.current_user = None
    st.success("👋 Logged out successfully.")

elif choice == "📂 Store Data":
    if not st.session_state.current_user:
        st.warning("🔐 Please log in first.")
    else:
        st.subheader(f"📂 Store Data - {st.session_state.current_user}")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter a Passkey:", type="password")
        if st.button("Encrypt & Save"):
            if user_data and passkey:
                encrypted = encrypt_data(user_data)
                hashed_passkey = hash_text(passkey)
                st.session_state.stored_data[st.session_state.current_user] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data stored securely.")
                st.code(encrypted)
            else:
                st.error("⚠️ All fields required.")

elif choice == "🔍 Retrieve Data":
    if not st.session_state.current_user:
        st.warning("🔐 Please log in first.")
    else:
        st.subheader(f"🔍 Retrieve Data - {st.session_state.current_user}")
        encrypted_text = st.text_area("Enter Your Encrypted Data:")
        passkey = st.text_input("Enter Your Passkey:", type="password")
        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted = decrypt_data(encrypted_text, passkey, st.session_state.current_user)
                if decrypted:
                    st.success(f"✅ Decrypted Data: {decrypted}")
                else:
                    st.error(f"❌ Incorrect passkey. Attempts left: {3 - st.session_state.failed_attempts}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. Redirecting to Login.")
                        st.session_state.current_user = None
                        st.rerun()
            else:
                st.error("⚠️ All fields required.")
