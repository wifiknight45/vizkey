#!/usr/bin/env python3
"""
pqc_visual_key_gui.py

Features:
- Generate PQC KEM + signature keypairs (liboqs via python-oqs)
- Derive deterministic seed via HKDF from private key material + optional user entropy
- Render deterministic colorful image from seed (Pillow + NumPy)
- Sign compact payload and embed public keys + signature into PNG metadata
- Encrypt metadata with AES-GCM (password-derived key) so metadata is hidden unless unlocked
- Tkinter GUI: live preview, Generate, Save (with encryption), Verify (decrypt+verify)
- Batch mode: CSV input -> generate many images and a verification CSV

Usage:
  python pqc_visual_key_gui.py
"""

import os
import sys
import io
import csv
import json
import binascii
import hashlib
import random
import datetime
import threading
import traceback

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from PIL import Image, ImageDraw, ImageFilter, ImageTk, PngImagePlugin
import numpy as np

# PQC and crypto
try:
    import oqs
except Exception as e:
    oqs = None

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------
# Crypto helpers
# -------------------------
def hkdf_from_bytes(input_bytes: bytes, length: int = 32, salt: bytes = b"pqc-visual-salt-v1", info: bytes = b"pqc-visual-info"):
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hk.derive(input_bytes)

def pbkdf2_key_from_password(password: str, salt: bytes, length: int = 32, iterations: int = 200000):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

def hex_to_bytes(h: str) -> bytes:
    return binascii.unhexlify(h.encode('ascii'))

# -------------------------
# PQC helpers (liboqs)
# -------------------------
def ensure_oqs_available():
    if oqs is None:
        raise RuntimeError("python-oqs (liboqs) not available. Install liboqs and python-oqs.")

def generate_pqc_keypairs(kem_name: str = "Kyber512", sig_name: str = "Dilithium2"):
    ensure_oqs_available()
    # KEM: generate keypair
    kem = oqs.KeyEncapsulation(kem_name)
    kem_public = kem.generate_keypair()
    # python-oqs may not expose private key directly; try export_secret_key if available
    try:
        kem_private = kem.export_secret_key()
    except Exception:
        # fallback: encapsulate to get shared secret and ciphertext as example; private key may be internal
        kem_private = b""
    # Signature keypair
    sig = oqs.Signature(sig_name)
    sig_public, sig_private = sig.generate_keypair()
    # return objects (caller must not keep private keys in insecure storage)
    return {
        "kem_name": kem_name,
        "sig_name": sig_name,
        "kem_public": kem_public,
        "kem_private": kem_private,
        "sig_public": sig_public,
        "sig_private": sig_private
    }

def sign_with_sig(sig_name: str, private_key: bytes, data: bytes) -> bytes:
    ensure_oqs_available()
    with oqs.Signature(sig_name) as s:
        return s.sign(data, private_key)

def verify_with_sig(sig_name: str, public_key: bytes, data: bytes, signature: bytes) -> bool:
    ensure_oqs_available()
    with oqs.Signature(sig_name) as s:
        return s.verify(data, signature, public_key)

# -------------------------
# Image generation
# -------------------------
def palette_from_hash(hexstr):
    cols = []
    for i in range(0, min(len(hexstr), 30), 6):
        try:
            r = int(hexstr[i:i+2], 16)
            g = int(hexstr[i+2:i+4], 16)
            b = int(hexstr[i+4:i+6], 16)
        except Exception:
            r,g,b = 128,128,128
        cols.append((r,g,b))
    if not cols:
        cols = [(32,160,200),(200,80,120),(240,200,60)]
    return cols

def generate_visual_from_seed(seed_bytes: bytes, size=(1024,1024)):
    seed_int = int.from_bytes(seed_bytes[:8], 'big')
    rng = random.Random(seed_int)
    hexhash = hashlib.sha256(seed_bytes).hexdigest()
    palette = palette_from_hash(hexhash)

    w,h = size
    base = Image.new('RGB', size, (0,0,0))
    draw = ImageDraw.Draw(base)

    # vertical gradient
    for y in range(h):
        t = y / max(1, h-1)
        c0 = palette[rng.randrange(len(palette))]
        c1 = palette[rng.randrange(len(palette))]
        col = tuple(int(c0[j]*(1-t) + c1[j]*t) for j in range(3))
        draw.line([(0,y),(w,y)], fill=col)

    # noise layer
    noise = (np.random.RandomState(rng.randint(0,2**31)).rand(h,w) * 255).astype(np.uint8)
    noise_img = Image.fromarray(noise).convert('RGB').filter(ImageFilter.GaussianBlur(radius=2))
    base = Image.blend(base, noise_img, alpha=0.22)

    # voronoi-like cells
    pts = [(rng.randint(0,w-1), rng.randint(0,h-1)) for _ in range(rng.randint(30,120))]
    xs = np.arange(w, dtype=np.int32)
    ys = np.arange(h, dtype=np.int32)
    X, Y = np.meshgrid(xs, ys)
    best = np.full((h,w), 0, dtype=np.int32)
    bestd = np.full((h,w), 10**12, dtype=np.int64)
    for i,(px,py) in enumerate(pts):
        d = (X - px).astype(np.int64)**2 + (Y - py).astype(np.int64)**2
        mask = d < bestd
        bestd[mask] = d[mask]
        best[mask] = i
    arr = np.zeros((h,w,3), dtype=np.uint8)
    for i in range(len(pts)):
        arr[best==i] = palette[i % len(palette)]
    vor = Image.fromarray(arr).filter(ImageFilter.GaussianBlur(radius=3))
    base = Image.blend(base, vor, alpha=0.36)

    # translucent shapes
    draw = ImageDraw.Draw(base, 'RGBA')
    for _ in range(rng.randint(18,48)):
        x0 = rng.randint(0,w); y0 = rng.randint(0,h)
        r = rng.randint(20, max(40, w//8))
        color = palette[rng.randrange(len(palette))] + (rng.randint(60,150),)
        draw.ellipse([x0-r,y0-r,x0+r,y0+r], fill=color)

    base = base.filter(ImageFilter.UnsharpMask(radius=2, percent=120, threshold=3))
    return base, hexhash

# -------------------------
# Metadata encryption helpers
# -------------------------
def encrypt_metadata_json(metadata: dict, password: str):
    """
    Returns dict with fields:
      - enc_salt_hex: hex salt for PBKDF2
      - enc_nonce_hex: hex nonce for AESGCM
      - enc_blob_hex: hex ciphertext (AESGCM)
    """
    salt = os.urandom(16)
    key = pbkdf2_key_from_password(password, salt, length=32)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode('utf-8')
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "enc_salt_hex": bytes_to_hex(salt),
        "enc_nonce_hex": bytes_to_hex(nonce),
        "enc_blob_hex": bytes_to_hex(ct)
    }

def decrypt_metadata_json(enc_salt_hex: str, enc_nonce_hex: str, enc_blob_hex: str, password: str):
    salt = hex_to_bytes(enc_salt_hex)
    nonce = hex_to_bytes(enc_nonce_hex)
    ct = hex_to_bytes(enc_blob_hex)
    key = pbkdf2_key_from_password(password, salt, length=32)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode('utf-8'))

# -------------------------
# High-level generate/verify flows
# -------------------------
def generate_pqc_visual_image(kem_alg="Kyber512", sig_alg="Dilithium2", size=1024, user_entropy: bytes = b""):
    """
    Generate PQC keypairs, derive seed, create image, sign payload.
    Returns dict with:
      - image (PIL.Image)
      - image_hash (hex)
      - kem_public_hex, sig_public_hex, signature_hex
      - kem_alg, sig_alg
      - private_material (bytes)  # caller must handle securely
    """
    ensure_oqs_available()
    kp = generate_pqc_keypairs(kem_alg, sig_alg)
    # derive seed from private material + optional user entropy
    seed_input = kp["sig_private"] + kp["kem_private"] + user_entropy
    seed = hkdf_from_bytes(seed_input, length=32, salt=b"pqc-visual-seed", info=b"visual-key-seed")
    img, img_hash = generate_visual_from_seed(seed, size=(size,size))
    # sign compact payload: SHA256(kem_pub || sig_pub || img_hash)
    payload = hashlib.sha256(kp["kem_public"] + kp["sig_public"] + img_hash.encode('ascii')).digest()
    signature = sign_with_sig(kp["sig_name"], kp["sig_private"], payload)
    return {
        "image": img,
        "image_hash": img_hash,
        "kem_public": kp["kem_public"],
        "sig_public": kp["sig_public"],
        "signature": signature,
        "kem_alg": kp["kem_name"],
        "sig_alg": kp["sig_name"],
        "private_material": {
            "kem_private": kp["kem_private"],
            "sig_private": kp["sig_private"]
        }
    }

def save_image_with_encrypted_metadata(image: Image.Image, out_path: str, kem_public: bytes, sig_public: bytes, signature: bytes, image_hash: str, kem_alg: str, sig_alg: str, password: str):
    """
    Encrypt metadata with password and save PNG with:
      - EncSalt, EncNonce, EncBlob (text chunks)
      - ImageHash (plaintext for quick reference)
      - Alg names (plaintext)
    """
    metadata = {
        "kem_public_hex": bytes_to_hex(kem_public),
        "sig_public_hex": bytes_to_hex(sig_public),
        "signature_hex": bytes_to_hex(signature),
        "image_hash": image_hash,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "kem_alg": kem_alg,
        "sig_alg": sig_alg
    }
    enc = encrypt_metadata_json(metadata, password)
    pnginfo = PngImagePlugin.PngInfo()
    # store encryption fields (visible) and a short image hash (visible)
    pnginfo.add_text("EncSalt", enc["enc_salt_hex"])
    pnginfo.add_text("EncNonce", enc["enc_nonce_hex"])
    pnginfo.add_text("EncBlob", enc["enc_blob_hex"])
    pnginfo.add_text("ImageHash", image_hash)
    pnginfo.add_text("KEM", kem_alg)
    pnginfo.add_text("SIG", sig_alg)
    image.save(out_path, "PNG", pnginfo=pnginfo)

def verify_image_file(path: str, password: str):
    """
    Extract encryption fields, decrypt metadata with password, verify signature.
    Returns dict with keys:
      - ok: bool
      - reason: str (if not ok)
      - metadata: dict (if ok)
    """
    ensure_oqs_available()
    img = Image.open(path)
    info = img.info
    required = ["EncSalt", "EncNonce", "EncBlob", "ImageHash", "KEM", "SIG"]
    for k in required:
        if k not in info:
            return {"ok": False, "reason": f"Missing PNG field: {k}"}
    try:
        meta = decrypt_metadata_json(info["EncSalt"], info["EncNonce"], info["EncBlob"], password)
    except Exception as e:
        return {"ok": False, "reason": f"Decryption failed: {e}"}
    # verify signature
    kem_pub = hex_to_bytes(meta["kem_public_hex"])
    sig_pub = hex_to_bytes(meta["sig_public_hex"])
    signature = hex_to_bytes(meta["signature_hex"])
    image_hash = meta["image_hash"]
    payload = hashlib.sha256(kem_pub + sig_pub + image_hash.encode('ascii')).digest()
    try:
        ok = verify_with_sig(meta["sig_alg"], sig_pub, payload, signature)
    except Exception as e:
        return {"ok": False, "reason": f"Signature verification error: {e}"}
    return {"ok": ok, "metadata": meta}

# -------------------------
# Batch mode
# -------------------------
def batch_generate_from_csv(csv_path: str, out_dir: str, kem_alg: str, sig_alg: str, size: int, password: str, entropy_column: str = None):
    """
    CSV expected to have at least an 'id' column. Optional entropy column name can be provided.
    For each row, generate an image and save as {id}.png. Produce a verification CSV with results.
    """
    results = []
    os.makedirs(out_dir, exist_ok=True)
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            identifier = row.get('id') or row.get('ID') or row.get('name') or row.get('Name')
            if not identifier:
                identifier = str(len(results)+1)
            entropy_hex = None
            if entropy_column and entropy_column in row and row[entropy_column].strip():
                entropy_hex = row[entropy_column].strip()
            user_entropy = hex_to_bytes(entropy_hex) if entropy_hex else b""
            try:
                out_path = os.path.join(out_dir, f"{identifier}.png")
                gen = generate_pqc_visual_image(kem_alg=kem_alg, sig_alg=sig_alg, size=size, user_entropy=user_entropy)
                save_image_with_encrypted_metadata(gen["image"], out_path, gen["kem_public"], gen["sig_public"], gen["signature"], gen["image_hash"], gen["kem_alg"], gen["sig_alg"], password)
                results.append({"id": identifier, "out": out_path, "image_hash": gen["image_hash"], "status": "ok"})
            except Exception as e:
                results.append({"id": identifier, "out": "", "image_hash": "", "status": f"error: {e}"})
    # write verification CSV
    ver_csv = os.path.join(out_dir, "batch_verification.csv")
    with open(ver_csv, 'w', newline='', encoding='utf-8') as vf:
        w = csv.DictWriter(vf, fieldnames=["id","out","image_hash","status"])
        w.writeheader()
        for r in results:
            w.writerow(r)
    return {"results": results, "verification_csv": ver_csv}

# -------------------------
# Tkinter GUI
# -------------------------
class PQCVisualGUI:
    def __init__(self, root):
        self.root = root
        root.title("PQC Visual Key Generator (GUI)")
        self.frame = ttk.Frame(root, padding=10)
        self.frame.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # Inputs
        ttk.Label(self.frame, text="KEM algorithm").grid(column=0, row=0, sticky="w")
        self.kem_var = tk.StringVar(value="Kyber512")
        self.kem_entry = ttk.Entry(self.frame, textvariable=self.kem_var, width=20)
        self.kem_entry.grid(column=0, row=1, sticky="w")

        ttk.Label(self.frame, text="Signature algorithm").grid(column=0, row=2, sticky="w")
        self.sig_var = tk.StringVar(value="Dilithium2")
        self.sig_entry = ttk.Entry(self.frame, textvariable=self.sig_var, width=20)
        self.sig_entry.grid(column=0, row=3, sticky="w")

        ttk.Label(self.frame, text="Optional user entropy (hex)").grid(column=0, row=4, sticky="w")
        self.entropy_var = tk.StringVar()
        self.entropy_entry = ttk.Entry(self.frame, textvariable=self.entropy_var, width=40)
        self.entropy_entry.grid(column=0, row=5, sticky="w")

        ttk.Label(self.frame, text="Image size (square)").grid(column=0, row=6, sticky="w")
        self.size_var = tk.StringVar(value="1024")
        self.size_combo = ttk.Combobox(self.frame, textvariable=self.size_var, values=["512","800","1024","2048"], width=10)
        self.size_combo.grid(column=0, row=7, sticky="w")

        # Password for metadata encryption
        ttk.Label(self.frame, text="Metadata password (for encryption)").grid(column=0, row=8, sticky="w")
        self.meta_pass_var = tk.StringVar()
        self.meta_pass_entry = ttk.Entry(self.frame, textvariable=self.meta_pass_var, width=30, show="*")
        self.meta_pass_entry.grid(column=0, row=9, sticky="w")

        # Buttons
        self.generate_btn = ttk.Button(self.frame, text="Generate (single)", command=self.on_generate)
        self.generate_btn.grid(column=0, row=10, pady=(8,0), sticky="w")
        self.save_btn = ttk.Button(self.frame, text="Save Image As...", command=self.on_save, state="disabled")
        self.save_btn.grid(column=0, row=10, padx=(140,0), sticky="w")
        self.verify_btn = ttk.Button(self.frame, text="Verify Image...", command=self.on_verify)
        self.verify_btn.grid(column=0, row=11, pady=(6,0), sticky="w")

        # Batch
        ttk.Separator(self.frame, orient="horizontal").grid(column=0, row=12, columnspan=3, sticky="ew", pady=8)
        ttk.Label(self.frame, text="Batch generation (CSV)").grid(column=0, row=13, sticky="w")
        ttk.Label(self.frame, text="CSV must have 'id' column; optional entropy column name:").grid(column=0, row=14, sticky="w")
        self.batch_entropy_col_var = tk.StringVar()
        self.batch_entropy_entry = ttk.Entry(self.frame, textvariable=self.batch_entropy_col_var, width=20)
        self.batch_entropy_entry.grid(column=0, row=15, sticky="w")
        self.batch_btn = ttk.Button(self.frame, text="Select CSV and Run Batch", command=self.on_batch)
        self.batch_btn.grid(column=0, row=16, pady=(6,0), sticky="w")

        # Preview and info
        self.preview_label = ttk.Label(self.frame, text="Preview")
        self.preview_label.grid(column=1, row=0, sticky="w")
        self.canvas = tk.Canvas(self.frame, width=512, height=512, bg="#111")
        self.canvas.grid(column=1, row=1, rowspan=12, padx=(10,0))

        ttk.Label(self.frame, text="ImageHash").grid(column=1, row=13, sticky="w")
        self.image_hash_var = tk.StringVar()
        self.image_hash_entry = ttk.Entry(self.frame, textvariable=self.image_hash_var, width=60, state="readonly")
        self.image_hash_entry.grid(column=1, row=14, sticky="w")

        ttk.Label(self.frame, text="Status").grid(column=1, row=15, sticky="w")
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.frame, textvariable=self.status_var)
        self.status_label.grid(column=1, row=16, sticky="w")

        # Internal
        self.current_image = None
        self.current_image_hash = None
        self.current_kem_pub = None
        self.current_sig_pub = None
        self.current_signature = None
        self.lock = threading.Lock()

    def set_status(self, text):
        self.status_var.set(text)
        self.root.update_idletasks()

    def on_generate(self):
        try:
            size = int(self.size_var.get())
        except Exception:
            messagebox.showerror("Invalid size", "Choose a valid size")
            return
        kem = self.kem_var.get().strip()
        sig = self.sig_var.get().strip()
        entropy_hex = self.entropy_var.get().strip()
        user_entropy = hex_to_bytes(entropy_hex) if entropy_hex else b""
        self.generate_btn.config(state="disabled")
        self.save_btn.config(state="disabled")
        self.set_status("Generating...")
        thread = threading.Thread(target=self._worker_generate, args=(kem, sig, size, user_entropy))
        thread.daemon = True
        thread.start()

    def _worker_generate(self, kem, sig, size, user_entropy):
        try:
            gen = generate_pqc_visual_image(kem_alg=kem, sig_alg=sig, size=size, user_entropy=user_entropy)
            with self.lock:
                self.current_image = gen["image"]
                self.current_image_hash = gen["image_hash"]
                self.current_kem_pub = gen["kem_public"]
                self.current_sig_pub = gen["sig_public"]
                self.current_signature = gen["signature"]
            self.root.after(0, self._update_preview_after_generate)
        except Exception as e:
            tb = traceback.format_exc()
            self.root.after(0, lambda: messagebox.showerror("Generation error", f"{e}\n\n{tb}"))
            self.root.after(0, lambda: self.generate_btn.config(state="normal"))
            self.root.after(0, lambda: self.set_status("Ready"))

    def _update_preview_after_generate(self):
        if self.current_image is None:
            return
        canvas_w = int(self.canvas['width'])
        canvas_h = int(self.canvas['height'])
        preview = self.current_image.copy()
        preview.thumbnail((canvas_w, canvas_h), Image.LANCZOS)
        self.tk_preview = ImageTk.PhotoImage(preview)
        self.canvas.delete("all")
        self.canvas.create_image(canvas_w//2, canvas_h//2, image=self.tk_preview)
        self.image_hash_var.set(self.current_image_hash)
        self.save_btn.config(state="normal")
        self.generate_btn.config(state="normal")
        self.set_status("Generated")

    def on_save(self):
        if self.current_image is None:
            messagebox.showinfo("No image", "Generate an image first")
            return
        out = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image","*.png")])
        if not out:
            return
        password = self.meta_pass_var.get()
        if not password:
            if not messagebox.askyesno("No password", "You did not enter a metadata password. Metadata will be encrypted with a random password (not recoverable). Continue?"):
                return
            # generate a random password and show it to user
            password = bytes_to_hex(os.urandom(12))
            messagebox.showinfo("Generated password", f"A random metadata password was generated. Save it securely:\n\n{password}")
        try:
            save_image_with_encrypted_metadata(self.current_image, out, self.current_kem_pub, self.current_sig_pub, self.current_signature, self.current_image_hash, self.kem_var.get(), self.sig_var.get(), password)
            self.set_status(f"Saved {out}")
            messagebox.showinfo("Saved", f"Image saved to {out}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def on_verify(self):
        path = filedialog.askopenfilename(filetypes=[("PNG image","*.png")])
        if not path:
            return
        password = self.meta_pass_var.get()
        if not password:
            password = simple_password_prompt(self.root, "Enter metadata password for verification")
            if password is None:
                return
        self.set_status("Verifying...")
        thread = threading.Thread(target=self._worker_verify, args=(path, password))
        thread.daemon = True
        thread.start()

    def _worker_verify(self, path, password):
        try:
            res = verify_image_file(path, password)
            if res.get("ok"):
                meta = res.get("metadata")
                msg = f"Verification OK\nKEM: {meta.get('kem_alg')}\nSIG: {meta.get('sig_alg')}\nImageHash: {meta.get('image_hash')}\nGeneratedAt: {meta.get('generated_at')}"
                self.root.after(0, lambda: messagebox.showinfo("Verified", msg))
                self.root.after(0, lambda: self.set_status("Verified OK"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Verification failed", res.get("reason")))
                self.root.after(0, lambda: self.set_status("Verification failed"))
        except Exception as e:
            tb = traceback.format_exc()
            self.root.after(0, lambda: messagebox.showerror("Verification error", f"{e}\n\n{tb}"))
            self.root.after(0, lambda: self.set_status("Ready"))

    def on_batch(self):
        csv_path = filedialog.askopenfilename(filetypes=[("CSV files","*.csv")])
        if not csv_path:
            return
        out_dir = filedialog.askdirectory(title="Select output directory for batch images")
        if not out_dir:
            return
        kem = self.kem_var.get().strip()
        sig = self.sig_var.get().strip()
        try:
            size = int(self.size_var.get())
        except Exception:
            messagebox.showerror("Invalid size", "Choose a valid size")
            return
        password = self.meta_pass_var.get()
        if not password:
            messagebox.showerror("Password required", "Enter a metadata password to encrypt batch metadata")
            return
        entropy_col = self.batch_entropy_col_var.get().strip() or None
        self.batch_btn.config(state="disabled")
        self.set_status("Running batch...")
        thread = threading.Thread(target=self._worker_batch, args=(csv_path, out_dir, kem, sig, size, password, entropy_col))
        thread.daemon = True
        thread.start()

    def _worker_batch(self, csv_path, out_dir, kem, sig, size, password, entropy_col):
        try:
            res = batch_generate_from_csv(csv_path, out_dir, kem, sig, size, password, entropy_column=entropy_col)
            msg = f"Batch complete. Verification CSV: {res['verification_csv']}"
            self.root.after(0, lambda: messagebox.showinfo("Batch complete", msg))
            self.root.after(0, lambda: self.set_status("Batch complete"))
        except Exception as e:
            tb = traceback.format_exc()
            self.root.after(0, lambda: messagebox.showerror("Batch error", f"{e}\n\n{tb}"))
            self.root.after(0, lambda: self.set_status("Ready"))
        finally:
            self.root.after(0, lambda: self.batch_btn.config(state="normal"))

def simple_password_prompt(parent, prompt):
    dlg = tk.Toplevel(parent)
    dlg.title("Password")
    ttk.Label(dlg, text=prompt).grid(column=0, row=0, padx=10, pady=6)
    pw_var = tk.StringVar()
    pw_entry = ttk.Entry(dlg, textvariable=pw_var, show="*")
    pw_entry.grid(column=0, row=1, padx=10, pady=6)
    result = {"pw": None}
    def on_ok():
        result["pw"] = pw_var.get()
        dlg.destroy()
    def on_cancel():
        dlg.destroy()
    ttk.Button(dlg, text="OK", command=on_ok).grid(column=0, row=2, sticky="w", padx=10, pady=6)
    ttk.Button(dlg, text="Cancel", command=on_cancel).grid(column=0, row=2, sticky="e", padx=10, pady=6)
    pw_entry.focus_set()
    parent.wait_window(dlg)
    return result["pw"]

# -------------------------
# Run GUI
# -------------------------
def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    app = PQCVisualGUI(root)
    root.geometry("1200x700")
    root.mainloop()

if __name__ == "__main__":
    main()
