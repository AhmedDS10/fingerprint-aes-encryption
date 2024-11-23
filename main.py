import os
import base64
import streamlit as st
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
# Streamlit App
# ===========================

def main():
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

      if st.button("Start Encryption"):
          if fingerprint_file is None or plaintext_file is None:
              st.error(":warning: Please upload both fingerprint data and the file to encrypt.")
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

              # Optionally, display base64 string
              # st.text("Base64 Encrypted Data:")
              # st.text(encrypted_b64)

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
  st.sidebar.image("files/aes_256_bot.jpg", caption="To receive fingerprint data" , use_column_width=True)
  st.sidebar.image("files/chat_id_bot.jpg", caption="To get the chat ID" , use_column_width=True)
  ##st.sidebar.success("The integration of biometric authentication, particularly fingerprint recognition, with encryption methods like AES-256 offers a robust solution for securing sensitive data. This approach combines the unique characteristics of fingerprints with the strength of AES-256 encryption to enhance data security.")

if __name__ == "__main__":
  main()