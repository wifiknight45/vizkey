A small toolkit that generates verifiable visual keys from post‑quantum cryptographic (PQC) key material. The program creates colorful deterministic images derived from PQC keypairs, embeds signed metadata (public keys + signature) into PNG files, and optionally encrypts that metadata with AES‑GCM. Includes a Tkinter GUI (live preview, Save, Verify) and a batch mode for automated generation and verification.

Features
PQC key generation (KEM + signature) via python-oqs (liboqs).

Deterministic image generation from HKDF-derived seeds (Pillow + NumPy).

Signed metadata: public keys and a signature are embedded with the image for verification.

Encrypted metadata: AES‑GCM with a password (PBKDF2-derived key) hides public keys/signature until unlocked.

Tkinter GUI: live preview, Generate, Save (encrypt metadata), Verify, and Batch controls.

Batch mode: CSV → many images + verification CSV for pipelines.

Requirements and installation
System prerequisites

Python 3.8+

liboqs (native library) installed on your system before installing python-oqs. See liboqs project docs for platform-specific build/install steps.

Python packages
Create a virtual environment and install packages:

bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
Example requirements.txt (included with the project)

text
python-oqs>=0.8.0
cryptography>=40.0.0
Pillow>=9.0.0
numpy>=1.24.0
If python-oqs fails to install, follow liboqs build instructions for your OS, then reinstall python-oqs.

Quick usage
Run the GUI
bash
source venv/bin/activate
python pqc_visual_key_gui.py
Enter KEM and Signature algorithm names (defaults: Kyber512, Dilithium2).

Optionally provide user entropy (hex) and a metadata password (used to encrypt metadata).

Click Generate to preview. Click Save Image As... to export a PNG with encrypted metadata.

Use Verify Image... to open a PNG, enter the metadata password, and verify the embedded signature.

CLI batch mode (headless)
A simple example to run the same flows in batch (CSV → images). The GUI exposes the same batch function; a headless wrapper can call:

bash
python -c "from pqc_visual_key_gui import batch_generate_from_csv; batch_generate_from_csv('input.csv','out_dir','Kyber512','Dilithium2',1024,'your-password','entropy_col')"
CSV format

Must include an id column (used to name output files).

Optional entropy column (hex) can be specified; its values are mixed into the seed for that row.

Batch outputs

One PNG per row named {id}.png in out_dir.

A batch_verification.csv summarizing results.

Security and operational notes
Do not use the image itself as a protocol key. Use the underlying PQC keypairs directly for encryption/signing operations. The image is a verifiable representation or auxiliary seed only.

Protect private keys. The program derives seeds from private key bytes; keep private material secure and avoid storing it in plaintext.

Metadata encryption: PNG text chunks are visible unless encrypted. AES‑GCM encryption uses a PBKDF2‑derived key from your password. If you lose the password, encrypted metadata cannot be recovered.

Entropy: user-supplied DOB or short passphrases are low entropy. Mix in strong secrets or external entropy for production use.

Library compatibility: python-oqs and liboqs APIs change; test with the exact versions you plan to deploy.

Interoperability: For real PQC operations, use the raw keypairs and vetted libraries/protocols; do not attempt to use image bytes directly as key material without proper KDF and format conversion.

Troubleshooting
python-oqs install errors: ensure liboqs is installed and visible to your compiler/linker. Follow liboqs build docs for your OS.

Slow generation: large image sizes (2048+) and batch jobs are CPU‑intensive. Use smaller sizes for previews and run batch jobs on a machine with sufficient CPU/RAM.

Decryption fails: verify you entered the correct metadata password; encryption uses PBKDF2 with a random salt stored in the PNG. If the password is lost, metadata is unrecoverable.

Signature verification fails: ensure the image file was not altered after saving; metadata integrity is required for verification.
