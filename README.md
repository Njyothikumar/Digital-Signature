Below is a rewritten `README.md` file tailored to the provided `digitalsignbot` code. It reflects the functionality, setup instructions, and usage details based on the Python script you shared.

---

# DigitalSignBot

DigitalSignBot is a Python-based desktop application that allows you to digitally sign your documents using an RSA key-pair and SHA-512 hashing algorithm. The application features a user-friendly graphical interface built with `tkinter` and leverages cryptographic libraries to generate keys, sign files, and verify signatures.

---

## Features

- **Key Generation**: Generate a 2048-bit RSA key-pair (public and private keys).
- **File Hashing**: Compute the SHA-512 hash of any uploaded file.
- **Digital Signing**: Sign the file's hash using the private key and save the signature.
- **Signature Verification**: Verify the authenticity of a signed file using the public key.
- **GUI**: Intuitive interface with pages for key generation, file upload, hashing, signing, and verification.

---

## Requirements

To run DigitalSignBot, you'll need Python 3.x and the following libraries:

- `tkinter` (usually included with Python)
- `pycryptodome` (for RSA key generation, signing, and verification)

Install the dependencies using the `requirements.txt` file (see [Installation](#installation) below).

---

## Installation

1. **Clone or Download the Repository**:
   ```bash
   git clone https://github.com/Njyothikumar/Digital-Signature.git
   cd digitalsignbot
   ```

2. **Set Up a Virtual Environment** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   Create a `requirements.txt` file with the following content:
   ```
   pycryptodome==3.20.0
   ```
   Then run:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**:
   ```bash
   python digitalsignbot.py
   ```

---

## Usage

1. **Launch the App**:
   Run the script, and a window titled "Digital Signer ✨" will appear.

2. **Generate Keys**:
   - Start on the "Key Generation" page.
   - Click "Generate Keys" to create an RSA key-pair.
   - The public and private keys will be displayed.
   - Save the public key as a `.pem` file when prompted.

3. **Upload a File**:
   - Navigate to the "Home" page by clicking "Next."
   - Click "Upload File" to select a document (e.g., a PDF or text file).
   - The app computes the SHA-512 hash of the file and displays it on the "File Hash" page.

4. **Sign the File**:
   - On the "Sign Your File" page, click "Sign Now."
   - Save the generated signature as a `.sig` file.
   - The app uses the private key to sign the file's hash.

5. **Verify the Signature**:
   - On the "Verify Signature" page, click "Verify Now."
   - Select the signature file (`.sig`) and the public key (`.pem`).
   - The app checks if the signature matches the file’s hash and displays the result.

---

## How It Works

- **Key Generation**: Uses `Crypto.PublicKey.RSA` to generate a 2048-bit RSA key-pair.
- **Hashing**: Computes a SHA-512 hash of the file using `hashlib.sha512`.
- **Signing**: Signs the hash with the private key using `pkcs1_15` from `Crypto.Signature`.
- **Verification**: Verifies the signature against the hash using the public key.


---

## Limitations

- The private key is displayed in the GUI but not automatically saved (you must copy it manually if needed).
- Only one file can be processed at a time.
- Requires clear user interaction for saving files (no default save paths).

---

## Future Improvements

- Add support for batch signing multiple files.
- Automatically save the private key securely with encryption.
- Enhance OCR integration to extract data from scanned documents before signing.
- Improve error handling for invalid file formats or corrupted keys.

---

## Contributing

Feel free to fork this repository, submit issues, or send pull requests with improvements!

---

## License

This project is open-source and available under the [MIT License](LICENSE).

---

## Contact

For questions or feedback, reach out to [jyothikumarnadigatla@gmail.com ].

---

This `README.md` provides a clear overview of the project based on the code you shared. You can copy this text into a `README.md` file in your project directory. If you need help creating the `requirements.txt` file, adding screenshots, or refining any section, let me know! What would you like to do next?
