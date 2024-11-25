# Fingerprint-Based AES-256 Encryption Application

A secure file encryption application that combines biometric authentication (fingerprint) with AES-256 encryption to protect sensitive data. Built with Streamlit and Python's cryptography library.

![Security Shield](files/main_logo.png)

## Features

- 🔐 AES-256 encryption in CBC mode
- 🔑 Fingerprint-based key derivation using PBKDF2HMAC
- 📁 Support for multiple file formats
- 🔄 Secure encryption and decryption operations
- 🌐 User-friendly web interface
- 🛡️ PKCS7 padding for secure data handling

## Prerequisites

```bash
pip install -r requirements.txt
```

Required packages:
- streamlit
- cryptography
- python-dotenv (optional, for environment variables)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd fingerprint-aes-encryption
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make sure you have the required image files in the `files` directory:
   - main_logo.png
   - aes_256_bot.jpg
   - chat_id_bot.jpg

## Usage

1. Run the Streamlit application:
```bash
streamlit run main.py
```

2. Access the application through your web browser (typically http://localhost:8501)

### Encrypting Files

1. Select "Encrypt File" from the sidebar
2. Upload your fingerprint data (supported formats: PNG, JPG, JPEG, BMP, BIN, TXT)
3. Upload the file you want to encrypt
4. Click "Start Encryption"
5. Download the encrypted file

### Decrypting Files

1. Select "Decrypt File" from the sidebar
2. Upload the encrypted file (.dat or .bin)
3. Upload the same fingerprint data used during encryption
4. Click "Start Decryption"
5. Download the decrypted file

## Security Features

- **Key Derivation**: Uses PBKDF2HMAC with SHA-256
- **Salt**: Random 16-byte salt for key derivation
- **Encryption**: AES-256 in CBC mode
- **IV**: Random 16-byte initialization vector for each encryption
- **Padding**: PKCS7 padding for data blocks

## File Format

Encrypted files contain:
- First 16 bytes: Salt
- Next 16 bytes: Initialization Vector (IV)
- Remaining bytes: Encrypted data

## Error Handling

The application includes comprehensive error handling for:
- Missing files
- Incorrect fingerprint data
- Corrupted encrypted files
- Key derivation failures
- Encryption/decryption failures

## Important Notes

1. Always keep your fingerprint data secure
2. Store encrypted files safely
3. Remember which fingerprint data was used for encryption
4. The same fingerprint data is required for decryption

## Directory Structure

```
.
├── main.py
├── requirements.txt
├── README.md
└── files/
    ├── main_logo.png
    ├── aes_256_bot.jpg
    └── chat_id_bot.jpg
```

## Technical Details

### Encryption Process
1. Fingerprint data → PBKDF2HMAC → AES-256 key
2. Random IV generation
3. PKCS7 padding of input data
4. AES-256-CBC encryption
5. Combination of salt + IV + ciphertext

### Decryption Process
1. Extraction of salt, IV, and ciphertext
2. Fingerprint data + salt → PBKDF2HMAC → AES-256 key
3. AES-256-CBC decryption
4. PKCS7 unpadding

## Contributing

Feel free to submit issues, fork the repository and create pull requests for any improvements.

## License

[MIT License](LICENSE)

## Safety Warning

This application is designed for secure file encryption. Always:
- Keep backup copies of important files
- Store fingerprint data securely
- Use strong fingerprint data
- Keep encrypted files safe