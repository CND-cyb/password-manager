# PyPass - Secure CLI Password Manager 🔐

**PyPass** is a robust, command-line interface (CLI) password manager written in Python. It focuses on local security, strong encryption standards, and user safety features like breach detection.

Designed as a cybersecurity project to demonstrate secure data handling and applied cryptography.

## ⚡ Features

- **Zero-Knowledge Architecture**: Your master password is never stored. It is used to derive the encryption key dynamically.
- **Strong Encryption**: Uses **AES-128** (via Fernet) for data encryption and **PBKDF2HMAC** (SHA-256) for key derivation.
- **Breach Detection**: Integrated with the **"Have I Been Pwned" API** to check if your passwords have leaked in known data breaches (k-anonymity model).
- **Secure Clipboard Handling**: Passwords are copied to the clipboard and automatically cleared after 10 seconds to prevent spying.
- **Password Generator**: Built-in tool to generate strong, random passwords using `secrets` (cryptographically strong random number generator).
- **Cross-Platform**: Works on Windows, Linux, and macOS.

## 🛡️ Security & Cryptography

This project implements industry-standard cryptographic primitives:

1.  **Key Derivation**: 
    The Master Password is not used directly as the encryption key. Instead, it is passed through a Key Derivation Function (KDF):
    * **Algorithm**: PBKDF2HMAC (SHA-256)
    * **Iterations**: 100,000 (to resist brute-force attacks)
    * **Salt**: A random 16-byte salt is generated for each vault to prevent Rainbow Table attacks.

2.  **Data Storage**:
    * The vault is stored in `data.txt`.
    * Format: `[Salt (Hex)] \n [Encrypted JSON Blob]`
    * The JSON blob is encrypted using **Fernet** (symmetric encryption based on AES in CBC mode with HMAC signing).

3.  **API Safety**:
    When checking for breached passwords, the full password is **never** sent to the API. Only the first 5 characters of its SHA-1 hash are sent (K-Anonymity), ensuring privacy.

## 📦 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/CND-cyb/pypass-manager.git)
    cd pypass-manager
    ```

2.  **Install dependencies:**
    ```bash
    pip install cryptography requests pyfiglet pyperclip
    ```

## 🚀 Usage

**Run the main script:**
```bash
python manager.py
```

## First Launch

You will be asked to define a **Master Password. ⚠️ Do not lose this password**. Since the system is zero-knowledge, there is no way to recover your data if you forget the master password.
Menu Options

    [a] Add: Save a new credential. You can generate a random password or input your own (which will be checked against leak databases).

    [v] View: Search for a site. If found, the password is copied to your clipboard for 10 seconds.

    [s] Remove: Delete credentials for a specific site.

    [q] Quit: Exit the application securely.

## ⚠️ Disclaimer

This tool is for **educational purposes**. While it uses strong cryptographic libraries, it has not undergone a third-party security audit. Use it to learn or for non-critical credentials.
