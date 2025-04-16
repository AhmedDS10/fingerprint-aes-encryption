import os
import base64
import streamlit as st
import requests
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ===========================
# Helper Functions
# ===========================

def derive_key(fingerprint_data, salt=None):
  """
  Derives a 256-bit AES key from fingerprint data using PBKDF2HMAC.

  :param fingerprint_data: Raw fingerprint data (bytes)
  :param salt: Optional salt. If not provided, a random salt is generated.
  :return: Tuple of (derived_key, salt)
  """
  if salt is None:
      salt = os.urandom(16)  # Generate a random 16-byte salt

  # Define KDF
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,  # 256 bits
      salt=salt,
      iterations=100_000,
      backend=default_backend()
  )

  key = kdf.derive(fingerprint_data)
  return key, salt

def encrypt_data(data, key):
  """
  Encrypts data using AES-256 in CBC mode with PKCS7 padding.

  :param data: Data to encrypt (bytes)
  :param key: AES-256 key (bytes)
  :return: Tuple of (iv, ciphertext)
  """
  iv = os.urandom(16)  # 128-bit IV for AES
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
  encryptor = cipher.encryptor()

  # Padding
  padder = padding.PKCS7(128).padder()
  padded_data = padder.update(data) + padder.finalize()

  # Encryption
  ciphertext = encryptor.update(padded_data) + encryptor.finalize()
  return iv, ciphertext

def decrypt_data(iv, ciphertext, key):
  """
  Decrypts data using AES-256 in CBC mode with PKCS7 padding.

  :param iv: Initialization Vector used during encryption (bytes)
  :param ciphertext: Encrypted data (bytes)
  :param key: AES-256 key (bytes)
  :return: Decrypted data (bytes)
  """
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
  decryptor = cipher.decryptor()

  # Decryption
  padded_data = decryptor.update(ciphertext) + decryptor.finalize()

  # Unpadding
  unpadder = padding.PKCS7(128).unpadder()
  data = unpadder.update(padded_data) + unpadder.finalize()
  return data

def save_encrypted_file(iv, ciphertext, salt):
  """
  Combines salt, IV, and ciphertext for storage.

  :param iv: Initialization Vector (bytes)
  :param ciphertext: Encrypted data (bytes)
  :param salt: Salt used for key derivation (bytes)
  :return: Combined bytes
  """
  return salt + iv + ciphertext

def load_encrypted_file(encrypted_data):
  """
  Extracts salt, IV, and ciphertext from the combined bytes.

  :param encrypted_data: Combined bytes (salt + iv + ciphertext)
  :return: Tuple of (salt, iv, ciphertext)
  """
  salt = encrypted_data[:16]
  iv = encrypted_data[16:32]
  ciphertext = encrypted_data[32:]
  return salt, iv, ciphertext

# ===========================
# Telegram Functions
# ===========================

def send_file_to_telegram(file_data, chat_id, bot_token, caption=None):
  """
  Sends a file to a Telegram chat using the Telegram Bot API.
  
  :param file_data: File data to send (bytes)
  :param chat_id: Telegram chat ID to send the file to
  :param bot_token: Telegram bot token
  :param caption: Optional message caption
  :return: True if successful, False otherwise
  """
  url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
  
  files = {
      'document': ('encrypted.dat', file_data, 'application/octet-stream')
  }
  
  data = {
      'chat_id': chat_id,
  }
  
  if caption:
      data['caption'] = caption
  
  try:
      response = requests.post(url, data=data, files=files)
      if response.status_code == 200:
          return True, "File sent successfully to Telegram!"
      else:
          return False, f"Error sending file: {response.text}"
  except Exception as e:
      return False, f"Error sending file: {str(e)}"

# ===========================
# Streamlit App
# ===========================

def main():
  # Telegram bot token
  BOT_TOKEN = "7379376090:AAEpzTK-itDBVwB68O5tqcgtKXUMSo_x0Y0"

  st.set_page_config(page_title="Fingerprint-Based AES-256 Encryption", page_icon="shield", layout="wide")
  st.image("files/main_logo.png", use_column_width=True)
  st.title(":shield: Fingerprint-Based AES-256 Encryption")
  st.markdown("""
Fingerprint-based AES-256 encryption is a security mechanism that combines biometric authentication with advanced encryption standards to protect sensitive data.
This approach leverages the uniqueness of an individual's fingerprint to enhance the security of the encryption and decryption processes.
""")

  menu = ["Encrypt File", "Decrypt File"]
  choice = st.sidebar.selectbox("Select Operation", menu)

  if choice == "Encrypt File":
      st.header(":lock: Encrypt a File")

      # Step 1: Upload Fingerprint Data
      st.subheader("1. Upload Fingerprint Data")
      fingerprint_file = st.file_uploader("Choose a fingerprint file", type=["png", "jpg", "jpeg", "bmp", "bin", "txt"])

      # Step 2: Upload File to Encrypt
      st.subheader("2. Upload File to Encrypt")
      plaintext_file = st.file_uploader("Choose a plaintext file", type=["txt", "pdf", "docx", "png", "jpg", "jpeg", "bmp", "bin"])
      
      # Step 3: Telegram Integration
      st.subheader("3. Telegram Integration (Optional)")
      send_to_telegram = st.checkbox("Send encrypted file to Telegram")
      
      telegram_chat_id = ""
      if send_to_telegram:
          telegram_chat_id = st.text_input("Enter Telegram Chat ID", help="This is the ID of the chat where you want to send the encrypted file.")

      if st.button("Start Encryption"):
          if fingerprint_file is None or plaintext_file is None:
              st.error(":warning: Please upload both fingerprint data and the file to encrypt.")
          elif send_to_telegram and not telegram_chat_id:
              st.error(":warning: Please enter a Telegram Chat ID or uncheck the 'Send to Telegram' option.")
          else:
              # Read fingerprint data
              fingerprint_data = fingerprint_file.read()

              # Derive key
              key, salt = derive_key(fingerprint_data)

              # Read plaintext data
              plaintext = plaintext_file.read()

              # Encrypt
              iv, ciphertext = encrypt_data(plaintext, key)

              # Combine salt + iv + ciphertext
              encrypted_combined = save_encrypted_file(iv, ciphertext, salt)

              # Encode to base64 for safe download
              encrypted_b64 = base64.b64encode(encrypted_combined).decode()

              # Provide download link
              st.success(":lock: Encryption Successful!")
              st.download_button(
                  label=":fire: Download Encrypted File",
                  data=encrypted_combined,
                  file_name="encrypted.dat",
                  mime="application/octet-stream"
              )
              
              # Send to Telegram if requested
              if send_to_telegram and telegram_chat_id:
                  with st.spinner("Sending to Telegram..."):
                      success, message = send_file_to_telegram(
                          encrypted_combined,
                          telegram_chat_id,
                          BOT_TOKEN,
                          caption="Encrypted file from Fingerprint-Based AES-256 Encryption app"
                      )
                      
                      if success:
                          st.success(f":rocket: {message}")
                      else:
                          st.error(f":warning: {message}")

  elif choice == "Decrypt File":
      st.header(":unlock: Decrypt a File")

      # Step 1: Upload Encrypted File
      st.subheader("1. Upload Encrypted File")
      encrypted_file = st.file_uploader("Choose the encrypted file", type=["dat", "bin"])

      # Step 2: Upload Fingerprint Data Used for Encryption
      st.subheader("2. Upload Fingerprint Data")
      fingerprint_file = st.file_uploader("Choose the fingerprint file used during encryption", type=["png", "jpg", "jpeg", "bmp", "bin", "txt"])

      if st.button("Start Decryption"):
          if encrypted_file is None or fingerprint_file is None:
              st.error(":warning: Please upload both the encrypted file and the fingerprint data used for encryption.")
          else:
              # Read encrypted data
              encrypted_data = encrypted_file.read()

              # Extract salt, iv, ciphertext
              try:
                  salt, iv, ciphertext = load_encrypted_file(encrypted_data)
              except Exception as e:
                  st.error(f"Error parsing the encrypted file: {e}")
                  return

              # Read fingerprint data
              fingerprint_data = fingerprint_file.read()

              # Derive key
              try:
                  key, _ = derive_key(fingerprint_data, salt=salt)
              except Exception as e:
                  st.error(f"Error deriving key: {e}")
                  return

              # Decrypt
              try:
                  decrypted_data = decrypt_data(iv, ciphertext, key)
              except Exception as e:
                  st.error(f"Decryption failed. Possible reasons: incorrect fingerprint data or corrupted encrypted file.\nError: {e}")
                  return

              # Provide download link
              st.success(":unlock: Decryption Successful!")
              st.download_button(
                  label=":fire: Download Decrypted File",
                  data=decrypted_data,
                  file_name="decrypted_file",
                  mime="application/octet-stream"
              )
              
  st.sidebar.markdown("---")
  st.sidebar.image("files/aes_256_bot.jpg", caption="To receive fingerprint data", use_column_width=True)
  st.sidebar.image("files/chat_id_bot.jpg", caption="To get the chat ID", use_column_width=True)

if __name__ == "__main__":
  main()
