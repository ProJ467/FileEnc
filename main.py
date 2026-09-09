import os
import io
import sys
import shutil
import zipfile
import tempfile
import subprocess
import threading
import base64
import secrets
import string
import struct
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================
# FileEnc 0.05V
# ============================================================

APP_NAME = "FileEnc"
APP_VERSION = "0.05V"


# ============================================================
# File formats
# ============================================================

OLD_FILE_MAGIC = b"FILEENC01"
OLD_FOLDER_MAGIC = b"FILEDIR01"

FILE_MAGIC_V2 = b"FILEENC02"
FOLDER_MAGIC_V2 = b"FILEDIR02"

# Current streaming/chunked format
FILE_MAGIC = b"FILEENC03"
FOLDER_MAGIC = b"FILEDIR03"


# ============================================================
# Crypto settings
# ============================================================

SALT_SIZE = 16
NONCE_SIZE = 12

AES_KEY_SIZE = 32              # 256 bits
GCM_TAG_SIZE = 16

PBKDF2_ITERATIONS = 600_000

CHUNK_SIZE = 1024 * 1024       # 1 MiB

MIN_PASSWORD_LENGTH = 8

MAX_ZIP_ENTRIES = 100_000
MAX_MEMBER_NAME_LENGTH = 4096


# ============================================================
# UI colors
# ============================================================

BG = "#0E1117"
CARD = "#171C24"
CARD_2 = "#1E2530"
INPUT_BG = "#0A0D12"
BORDER = "#2D3544"

TEXT = "#F3F5F7"
TEXT_MUTED = "#98A1B2"

ACCENT = "#6D8CFF"
ACCENT_HOVER = "#5877E8"

SUCCESS = "#55CC8A"
DANGER = "#E0646A"
WARNING = "#E2B85C"


# ============================================================
# Global state
# ============================================================

root = None
status_label = None


# ============================================================
# Utility
# ============================================================

def format_size(size):
    units = ["B", "KB", "MB", "GB", "TB"]

    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"

        value /= 1024


def center_window(window, width, height):
    window.update_idletasks()

    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)

    window.geometry(
        f"{width}x{height}+{x}+{y}"
    )


def set_status(text, color=TEXT_MUTED):
    if status_label is not None:
        status_label.config(
            text=text,
            fg=color
        )


def unique_path(path):
    path = Path(path)

    if not path.exists():
        return path

    counter = 1

    while True:
        candidate = path.with_name(
            f"{path.stem} ({counter}){path.suffix}"
        )

        if not candidate.exists():
            return candidate

        counter += 1


def same_path(a, b):
    try:
        return (
            Path(a).resolve()
            == Path(b).resolve()
        )
    except OSError:
        return (
            os.path.abspath(a)
            == os.path.abspath(b)
        )


def ask_overwrite(path):
    path = Path(path)

    if not path.exists():
        return True

    return messagebox.askyesno(
        APP_NAME,
        f"This path already exists:\n\n"
        f"{path}\n\n"
        "Overwrite it?",
        parent=root
    )


def remove_path(path):
    path = Path(path)

    if not path.exists():
        return

    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def atomic_write(path, data):
    """
    Safely write bytes using a temporary file and os.replace().
    """

    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            dir=str(path.parent),
            prefix=".fileenc_",
            suffix=".tmp"
        ) as temp:

            temp_path = Path(
                temp.name
            )

            temp.write(data)
            temp.flush()
            os.fsync(temp.fileno())

        os.replace(
            temp_path,
            path
        )

    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink(
                    missing_ok=True
                )
            except Exception:
                pass

        raise


# ============================================================
# Password helpers
# ============================================================

def password_strength(password):
    if not password:
        return "Empty", DANGER

    score = 0

    if len(password) >= 8:
        score += 1

    if len(password) >= 12:
        score += 1

    if any(
        c.islower()
        for c in password
    ):
        score += 1

    if any(
        c.isupper()
        for c in password
    ):
        score += 1

    if any(
        c.isdigit()
        for c in password
    ):
        score += 1

    if any(
        c in string.punctuation
        for c in password
    ):
        score += 1

    if score <= 2:
        return "Weak", DANGER

    if score <= 4:
        return "Medium", WARNING

    return "Strong", SUCCESS


def generate_password(length=20):
    if length < 12:
        length = 12

    alphabet = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*_-+=?"
    )

    while True:
        password = "".join(
            secrets.choice(alphabet)
            for _ in range(length)
        )

        strength, _ = password_strength(
            password
        )

        if strength == "Strong":
            return password


# ============================================================
# Password dialog
# ============================================================

def ask_password(
    title,
    confirm=False,
    require_strong=False
):
    window = tk.Toplevel(root)

    window.title(title)
    window.configure(bg=BG)
    window.resizable(False, False)

    window.transient(root)
    window.grab_set()

    center_window(
        window,
        470,
        380 if confirm else 330
    )

    result = {
        "password": None
    }

    card = tk.Frame(
        window,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    card.pack(
        fill="both",
        expand=True,
        padx=12,
        pady=12
    )

    tk.Label(
        card,
        text=title,
        bg=CARD,
        fg=TEXT,
        font=("Segoe UI", 15, "bold")
    ).pack(
        pady=(18, 15)
    )

    tk.Label(
        card,
        text="Password",
        bg=CARD,
        fg=TEXT_MUTED,
        font=("Segoe UI", 10)
    ).pack(
        anchor="w",
        padx=28
    )

    password_entry = tk.Entry(
        card,
        bg=INPUT_BG,
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        bd=0,
        show="*",
        font=("Segoe UI", 11)
    )

    password_entry.pack(
        fill="x",
        padx=28,
        pady=(5, 6),
        ipady=8
    )

    strength_label = tk.Label(
        card,
        text="Password strength: Empty",
        bg=CARD,
        fg=DANGER,
        font=("Segoe UI", 9, "bold")
    )

    strength_label.pack(
        anchor="w",
        padx=28,
        pady=(0, 10)
    )

    def update_strength(_event=None):
        strength, color = password_strength(
            password_entry.get()
        )

        strength_label.config(
            text=f"Password strength: {strength}",
            fg=color
        )

    password_entry.bind(
        "<KeyRelease>",
        update_strength
    )

    confirm_entry = None

    if confirm:
        tk.Label(
            card,
            text="Confirm password",
            bg=CARD,
            fg=TEXT_MUTED,
            font=("Segoe UI", 10)
        ).pack(
            anchor="w",
            padx=28
        )

        confirm_entry = tk.Entry(
            card,
            bg=INPUT_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            show="*",
            font=("Segoe UI", 11)
        )

        confirm_entry.pack(
            fill="x",
            padx=28,
            pady=(5, 12),
            ipady=8
        )

    options = tk.Frame(
        card,
        bg=CARD
    )

    options.pack(
        fill="x",
        padx=25,
        pady=(0, 12)
    )

    show_var = tk.BooleanVar(
        value=False
    )

    def toggle_show():
        show = "" if show_var.get() else "*"

        password_entry.config(
            show=show
        )

        if confirm_entry:
            confirm_entry.config(
                show=show
            )

    tk.Checkbutton(
        options,
        text="Show password",
        variable=show_var,
        command=toggle_show,
        bg=CARD,
        fg=TEXT_MUTED,
        activebackground=CARD,
        activeforeground=TEXT,
        selectcolor=CARD_2,
        highlightthickness=0,
        bd=0,
        font=("Segoe UI", 9)
    ).pack(
        side="left"
    )

    def use_generated_password():
        password = generate_password()

        password_entry.delete(
            0,
            tk.END
        )

        password_entry.insert(
            0,
            password
        )

        if confirm_entry:
            confirm_entry.delete(
                0,
                tk.END
            )

            confirm_entry.insert(
                0,
                password
            )

        update_strength()

    tk.Button(
        options,
        text="Generate",
        command=use_generated_password,
        bg=CARD_2,
        fg=TEXT,
        activebackground=BORDER,
        activeforeground=TEXT,
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Segoe UI", 9),
        padx=12,
        pady=5
    ).pack(
        side="right"
    )

    buttons = tk.Frame(
        card,
        bg=CARD
    )

    buttons.pack(
        fill="x",
        padx=28,
        pady=(2, 15)
    )

    def cancel():
        result["password"] = None
        window.destroy()

    def accept():
        password = password_entry.get()

        if not password:
            messagebox.showwarning(
                APP_NAME,
                "Password cannot be empty.",
                parent=window
            )
            password_entry.focus_set()
            return

        if require_strong:
            if len(password) < MIN_PASSWORD_LENGTH:
                messagebox.showwarning(
                    APP_NAME,
                    f"Password must contain at least "
                    f"{MIN_PASSWORD_LENGTH} characters.",
                    parent=window
                )
                password_entry.focus_set()
                return

            strength, _ = password_strength(
                password
            )

            if strength == "Weak":
                use_anyway = messagebox.askyesno(
                    APP_NAME,
                    "This password is weak.\n\n"
                    "Use it anyway?",
                    parent=window
                )

                if not use_anyway:
                    password_entry.focus_set()
                    return

        if confirm:
            if password != confirm_entry.get():
                messagebox.showerror(
                    APP_NAME,
                    "Passwords do not match.",
                    parent=window
                )
                confirm_entry.focus_set()
                return

        result["password"] = password
        window.destroy()

    tk.Button(
        buttons,
        text="Cancel",
        command=cancel,
        bg=CARD_2,
        fg=TEXT,
        activebackground=BORDER,
        activeforeground=TEXT,
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Segoe UI", 10),
        padx=20,
        pady=8
    ).pack(
        side="right",
        padx=(8, 0)
    )

    tk.Button(
        buttons,
        text="OK",
        command=accept,
        bg=ACCENT,
        fg="white",
        activebackground=ACCENT_HOVER,
        activeforeground="white",
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Segoe UI", 10, "bold"),
        padx=28,
        pady=8
    ).pack(
        side="right"
    )

    window.bind(
        "<Return>",
        lambda event: accept()
    )

    window.bind(
        "<Escape>",
        lambda event: cancel()
    )

    password_entry.focus_set()

    root.wait_window(window)

    return result["password"]


# ============================================================
# Key derivation
# ============================================================

def make_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )

    return kdf.derive(
        password.encode("utf-8")
    )


# ============================================================
# AES-256-GCM: Full V2 format
# ============================================================

def aes_encrypt_full(
    data,
    password,
    magic
):
    salt = os.urandom(
        SALT_SIZE
    )

    nonce = os.urandom(
        NONCE_SIZE
    )

    key = make_key(
        password,
        salt
    )

    ciphertext = AESGCM(
        key
    ).encrypt(
        nonce,
        data,
        magic
    )

    return (
        magic
        + salt
        + nonce
        + ciphertext
    )


def aes_decrypt_full(
    data,
    password,
    magic
):
    if not data.startswith(
        magic
    ):
        raise ValueError(
            "Invalid FileEnc V2 format."
        )

    header_size = (
        len(magic)
        + SALT_SIZE
        + NONCE_SIZE
    )

    if len(data) <= header_size + GCM_TAG_SIZE - 1:
        raise ValueError(
            "FileEnc V2 data is incomplete."
        )

    salt_start = len(magic)
    salt_end = (
        salt_start
        + SALT_SIZE
    )

    nonce_start = salt_end
    nonce_end = (
        nonce_start
        + NONCE_SIZE
    )

    salt = data[
        salt_start:salt_end
    ]

    nonce = data[
        nonce_start:nonce_end
    ]

    ciphertext = data[
        nonce_end:
    ]

    key = make_key(
        password,
        salt
    )

    try:
        return AESGCM(
            key
        ).decrypt(
            nonce,
            ciphertext,
            magic
        )

    except InvalidTag:
        raise ValueError(
            "Wrong password or corrupted "
            "FileEnc V2 file."
        )


# ============================================================
# AES-256-GCM: Chunked V3 format
# ============================================================

def aes_encrypt_stream(
    in_path,
    out_path,
    password,
    magic
):
    """
    FileEnc 03 format:

        MAGIC
        SALT

        repeated:
            4-byte big-endian plaintext length
            12-byte nonce
            ciphertext + 16-byte GCM tag

        4-byte zero terminator

    The explicit chunk length fixes the old framing bug.
    """

    salt = os.urandom(
        SALT_SIZE
    )

    key = make_key(
        password,
        salt
    )

    aesgcm = AESGCM(
        key
    )

    with open(
        in_path,
        "rb"
    ) as source, open(
        out_path,
        "wb"
    ) as destination:

        destination.write(
            magic
        )

        destination.write(
            salt
        )

        while True:
            chunk = source.read(
                CHUNK_SIZE
            )

            if not chunk:
                break

            if len(chunk) > CHUNK_SIZE:
                raise ValueError(
                    "Internal chunk size error."
                )

            nonce = os.urandom(
                NONCE_SIZE
            )

            ciphertext = aesgcm.encrypt(
                nonce,
                chunk,
                magic
            )

            destination.write(
                struct.pack(
                    ">I",
                    len(chunk)
                )
            )

            destination.write(
                nonce
            )

            destination.write(
                ciphertext
            )

        # End marker
        destination.write(
            struct.pack(
                ">I",
                0
            )
        )


def aes_decrypt_stream(
    in_path,
    out_path,
    password,
    magic
):
    """
    Decrypt FileEnc 03.

    Every chunk tells us its exact plaintext length,
    so the next nonce can never be swallowed accidentally.
    """

    with open(
        in_path,
        "rb"
    ) as source:

        header = source.read(
            len(magic)
        )

        if header != magic:
            raise ValueError(
                "Invalid FileEnc 03 format."
            )

        salt = source.read(
            SALT_SIZE
        )

        if len(salt) != SALT_SIZE:
            raise ValueError(
                "FileEnc file is truncated."
            )

        key = make_key(
            password,
            salt
        )

        aesgcm = AESGCM(
            key
        )

        total_plaintext = 0
        saw_terminator = False

        with open(
            out_path,
            "wb"
        ) as destination:

            while True:
                length_bytes = source.read(
                    4
                )

                if len(length_bytes) != 4:
                    raise ValueError(
                        "FileEnc file is truncated "
                        "or missing its end marker."
                    )

                plaintext_length = struct.unpack(
                    ">I",
                    length_bytes
                )[0]

                # End marker
                if plaintext_length == 0:
                    saw_terminator = True
                    break

                if plaintext_length > CHUNK_SIZE:
                    raise ValueError(
                        "Invalid chunk length."
                    )

                nonce = source.read(
                    NONCE_SIZE
                )

                if len(nonce) != NONCE_SIZE:
                    raise ValueError(
                        "FileEnc chunk is truncated."
                    )

                ciphertext_length = (
                    plaintext_length
                    + GCM_TAG_SIZE
                )

                ciphertext = source.read(
                    ciphertext_length
                )

                if len(ciphertext) != ciphertext_length:
                    raise ValueError(
                        "FileEnc ciphertext chunk is truncated."
                    )

                try:
                    plaintext = aesgcm.decrypt(
                        nonce,
                        ciphertext,
                        magic
                    )

                except InvalidTag:
                    raise ValueError(
                        "Wrong password or corrupted "
                        "FileEnc data."
                    )

                if len(plaintext) != plaintext_length:
                    raise ValueError(
                        "Decrypted chunk length mismatch."
                    )

                destination.write(
                    plaintext
                )

                total_plaintext += (
                    plaintext_length
                )

            if not saw_terminator:
                raise ValueError(
                    "FileEnc end marker missing."
                )

        # There must be absolutely nothing after the terminator.
        trailing = source.read(1)

        if trailing:
            raise ValueError(
                "Unexpected data found after FileEnc end marker."
            )

    return total_plaintext


# ============================================================
# Legacy Fernet support
# ============================================================

def legacy_decrypt_full(
    data,
    password,
    magic
):
    if not data.startswith(
        magic
    ):
        raise ValueError(
            "Invalid legacy FileEnc format."
        )

    salt_start = len(magic)

    salt_end = (
        salt_start
        + SALT_SIZE
    )

    if len(data) <= salt_end:
        raise ValueError(
            "Legacy FileEnc file is incomplete."
        )

    salt = data[
        salt_start:salt_end
    ]

    ciphertext = data[
        salt_end:
    ]

    key = make_key(
        password,
        salt
    )

    fernet_key = base64.urlsafe_b64encode(
        key
    )

    try:
        return Fernet(
            fernet_key
        ).decrypt(
            ciphertext
        )

    except InvalidToken:
        raise ValueError(
            "Wrong password or corrupted "
            "legacy FileEnc file."
        )


# ============================================================
# Format detection
# ============================================================

def detect_format(data):
    if data.startswith(
        FILE_MAGIC
    ):
        return "AES-256-GCM Chunked file"

    if data.startswith(
        FOLDER_MAGIC
    ):
        return "AES-256-GCM Chunked folder"

    if data.startswith(
        FILE_MAGIC_V2
    ):
        return "AES-256-GCM Full file"

    if data.startswith(
        FOLDER_MAGIC_V2
    ):
        return "AES-256-GCM Full folder"

    if data.startswith(
        OLD_FILE_MAGIC
    ):
        return "Legacy Fernet file"

    if data.startswith(
        OLD_FOLDER_MAGIC
    ):
        return "Legacy Fernet folder"

    return "Unknown"


# ============================================================
# Decrypt V3 to file
# ============================================================

def decrypt_to_path(
    source,
    output,
    password
):
    source_path = Path(source)
    output_path = Path(output)

    with open(
        source_path,
        "rb"
    ) as source_file:

        header = source_file.read(
            32
        )

    if header.startswith(
        FILE_MAGIC
    ):
        temp_output = output_path.with_name(
            "." + output_path.name + ".tmp"
        )

        try:
            aes_decrypt_stream(
                source_path,
                temp_output,
                password,
                FILE_MAGIC
            )

            os.replace(
                temp_output,
                output_path
            )

        except Exception:
            temp_output.unlink(
                missing_ok=True
            )
            raise

        return "AES-256-GCM Chunked"

    if header.startswith(
        FILE_MAGIC_V2
    ):
        data = source_path.read_bytes()

        decrypted = aes_decrypt_full(
            data,
            password,
            FILE_MAGIC_V2
        )

        atomic_write(
            output_path,
            decrypted
        )

        return "AES-256-GCM Full"

    if header.startswith(
        OLD_FILE_MAGIC
    ):
        data = source_path.read_bytes()

        decrypted = legacy_decrypt_full(
            data,
            password,
            OLD_FILE_MAGIC
        )

        atomic_write(
            output_path,
            decrypted
        )

        return "Legacy Fernet"

    raise ValueError(
        "Unknown FileEnc file format."
    )


# ============================================================
# Encrypt file
# ============================================================

def encrypt_file():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select file to encrypt"
    )

    if not source:
        return

    password = ask_password(
        "Encrypt file",
        confirm=True,
        require_strong=True
    )

    if password is None:
        return

    source_path = Path(
        source
    )

    output = filedialog.asksaveasfilename(
        parent=root,
        title="Where should the encrypted file be saved?",
        initialfile=(
            source_path.name
            + ".fenc"
        ),
        defaultextension=".fenc",
        filetypes=[
            (
                "FileEnc files",
                "*.fenc"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not output:
        return

    output_path = Path(
        output
    )

    if same_path(
        source_path,
        output_path
    ):
        messagebox.showerror(
            APP_NAME,
            "Output cannot be the original file.",
            parent=root
        )
        return

    if not ask_overwrite(
        output_path
    ):
        return

    def task():
        set_status(
            "Encrypting with AES-256-GCM...",
            ACCENT
        )

        temp_output = output_path.with_name(
            "." + output_path.name + ".tmp"
        )

        try:
            aes_encrypt_stream(
                source_path,
                temp_output,
                password,
                FILE_MAGIC
            )

            # Replace destination only after complete write.
            os.replace(
                temp_output,
                output_path
            )

        finally:
            temp_output.unlink(
                missing_ok=True
            )

    def worker():
        try:
            task()

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Encryption successful! ✅\n\n"
                    "Algorithm: AES-256-GCM\n"
                    f"Saved to:\n{output_path}",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:

            def failure():
                set_status(
                    "Encryption failed",
                    DANGER
                )

                messagebox.showerror(
                    "Encryption error",
                    str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Encrypt & Replace
# ============================================================

def encrypt_replace_file():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select file to encrypt and replace"
    )

    if not source:
        return

    source_path = Path(
        source
    )

    password = ask_password(
        "Encrypt & Replace",
        confirm=True,
        require_strong=True
    )

    if password is None:
        return

    output = filedialog.asksaveasfilename(
        parent=root,
        title="Where should the encrypted file be saved?",
        initialfile=(
            source_path.name
            + ".fenc"
        ),
        defaultextension=".fenc",
        filetypes=[
            (
                "FileEnc files",
                "*.fenc"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not output:
        return

    output_path = Path(
        output
    )

    if same_path(
        source_path,
        output_path
    ):
        messagebox.showerror(
            APP_NAME,
            "Encrypted output cannot be "
            "the source file.",
            parent=root
        )
        return

    if not ask_overwrite(
        output_path
    ):
        return

    confirm_delete = messagebox.askyesno(
        "Confirm Encrypt & Replace",
        "The original file will be deleted ONLY "
        "after successful encryption.\n\n"
        f"Original:\n{source_path}\n\n"
        f"Encrypted:\n{output_path}\n\n"
        "Continue?",
        icon="warning",
        parent=root
    )

    if not confirm_delete:
        return

    def worker():
        temp_output = output_path.with_name(
            "." + output_path.name + ".tmp"
        )

        try:
            set_status(
                "Encrypting and verifying...",
                ACCENT
            )

            aes_encrypt_stream(
                source_path,
                temp_output,
                password,
                FILE_MAGIC
            )

            # Verify by decrypting to a second temp file.
            verify_output = output_path.with_name(
                "." + output_path.name + ".verify"
            )

            try:
                aes_decrypt_stream(
                    temp_output,
                    verify_output,
                    password,
                    FILE_MAGIC
                )

                if not verify_output.exists():
                    raise ValueError(
                        "Verification output was not created."
                    )

                if (
                    verify_output.stat().st_size
                    != source_path.stat().st_size
                ):
                    raise ValueError(
                        "Verification size mismatch."
                    )

                verify_output.unlink(
                    missing_ok=True
                )

            finally:
                verify_output.unlink(
                    missing_ok=True
                )

            os.replace(
                temp_output,
                output_path
            )

            # Only now delete the source.
            source_path.unlink()

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Encrypt & Replace completed! ✅\n\n"
                    "The encrypted file was verified.\n"
                    "The original file was removed.",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:
            temp_output.unlink(
                missing_ok=True
            )

            def failure():
                set_status(
                    "Encrypt & Replace failed",
                    DANGER
                )

                messagebox.showerror(
                    "Encrypt & Replace error",
                    "The original file was kept.\n\n"
                    + str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Decrypt file
# ============================================================

def decrypt_file():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select encrypted file",
        filetypes=[
            (
                "FileEnc files",
                "*.fenc"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not source:
        return

    password = ask_password(
        "Decrypt file"
    )

    if password is None:
        return

    source_path = Path(
        source
    )

    if source_path.suffix.lower() == ".fenc":
        default_name = source_path.stem
    else:
        default_name = (
            source_path.name
            + ".decrypted"
        )

    output = filedialog.asksaveasfilename(
        parent=root,
        title="Where should the decrypted file be saved?",
        initialfile=default_name,
        filetypes=[
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not output:
        return

    output_path = Path(
        output
    )

    if same_path(
        source_path,
        output_path
    ):
        messagebox.showerror(
            APP_NAME,
            "Output cannot be the encrypted source.",
            parent=root
        )
        return

    if output_path.exists():
        if not ask_overwrite(
            output_path
        ):
            return

    def worker():
        try:
            set_status(
                "Decrypting...",
                ACCENT
            )

            format_name = decrypt_to_path(
                source_path,
                output_path,
                password
            )

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Decryption successful! ✅\n\n"
                    f"Format: {format_name}\n"
                    f"Saved to:\n{output_path}",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:

            def failure():
                try:
                    if output_path.exists():
                        output_path.unlink()
                except Exception:
                    pass

                set_status(
                    "Decryption failed",
                    DANGER
                )

                messagebox.showerror(
                    "Decryption error",
                    str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Decrypt & Replace
# ============================================================

def decrypt_replace_file():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select encrypted file to decrypt and replace",
        filetypes=[
            (
                "FileEnc files",
                "*.fenc"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not source:
        return

    source_path = Path(
        source
    )

    password = ask_password(
        "Decrypt & Replace"
    )

    if password is None:
        return

    if source_path.suffix.lower() == ".fenc":
        default_name = source_path.stem
    else:
        default_name = (
            source_path.name
            + ".decrypted"
        )

    output = filedialog.asksaveasfilename(
        parent=root,
        title="Where should the decrypted file be saved?",
        initialfile=default_name,
        filetypes=[
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not output:
        return

    output_path = Path(
        output
    )

    if same_path(
        source_path,
        output_path
    ):
        messagebox.showerror(
            APP_NAME,
            "Output cannot be the encrypted source.",
            parent=root
        )
        return

    if output_path.exists():
        if not ask_overwrite(
            output_path
        ):
            return

    confirm_delete = messagebox.askyesno(
        "Confirm Decrypt & Replace",
        "The encrypted source will be deleted ONLY "
        "after successful decryption.\n\n"
        f"Encrypted:\n{source_path}\n\n"
        f"Decrypted:\n{output_path}\n\n"
        "Continue?",
        icon="warning",
        parent=root
    )

    if not confirm_delete:
        return

    def worker():
        try:
            set_status(
                "Decrypting and verifying...",
                ACCENT
            )

            source_format = decrypt_to_path(
                source_path,
                output_path,
                password
            )

            # Additional size check against the source
            # is useful for detecting an incomplete result.
            # It does not replace GCM authentication.
            if not output_path.exists():
                raise ValueError(
                    "Decrypted output was not created."
                )

            source_path.unlink()

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Decrypt & Replace completed! ✅\n\n"
                    f"Format: {source_format}\n"
                    "The decrypted file was created.\n"
                    "The encrypted original was removed.",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:

            def failure():
                try:
                    if output_path.exists():
                        output_path.unlink()
                except Exception:
                    pass

                set_status(
                    "Decrypt & Replace failed",
                    DANGER
                )

                messagebox.showerror(
                    "Decrypt & Replace error",
                    "The encrypted original was kept.\n\n"
                    + str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Folder -> ZIP on disk
# ============================================================

def folder_to_zip_disk(
    folder,
    zip_path
):
    base = Path(
        folder
    ).resolve()

    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED
    ) as archive:

        for current_root, directories, files in os.walk(
            base
        ):
            current_root = Path(
                current_root
            )

            # Empty directories
            for directory in directories:
                directory_path = (
                    current_root / directory
                )

                try:
                    is_empty = not any(
                        directory_path.iterdir()
                    )
                except OSError:
                    is_empty = False

                if is_empty:
                    relative = (
                        directory_path.relative_to(
                            base
                        )
                    )

                    archive.writestr(
                        str(
                            relative
                        ).replace(
                            "\\",
                            "/"
                        ) + "/",
                        b""
                    )

            # Files
            for filename in files:
                file_path = (
                    current_root / filename
                )

                relative = (
                    file_path.relative_to(
                        base
                    )
                )

                archive.write(
                    file_path,
                    str(
                        relative
                    ).replace(
                        "\\",
                        "/"
                    )
                )


# ============================================================
# Secure ZIP extraction
# ============================================================

def secure_extract(
    zip_path,
    destination
):
    destination = Path(
        destination
    ).resolve()

    destination.mkdir(
        parents=True,
        exist_ok=True
    )

    with zipfile.ZipFile(
        zip_path,
        "r"
    ) as archive:

        members = archive.infolist()

        if len(members) > MAX_ZIP_ENTRIES:
            raise ValueError(
                "ZIP archive contains too many entries."
            )

        seen = set()

        for member in members:
            name = member.filename

            if len(name) > MAX_MEMBER_NAME_LENGTH:
                raise ValueError(
                    "ZIP entry name is too long."
                )

            normalized = name.replace(
                "\\",
                "/"
            )

            if normalized in seen:
                raise ValueError(
                    "Unsafe ZIP archive: "
                    "duplicate path detected."
                )

            seen.add(
                normalized
            )

            parts = Path(
                normalized
            ).parts

            # Absolute Unix path
            if normalized.startswith("/"):
                raise ValueError(
                    "Unsafe ZIP archive: "
                    "absolute path detected."
                )

            # Windows drive path
            if (
                parts
                and ":" in parts[0]
            ):
                raise ValueError(
                    "Unsafe ZIP archive: "
                    "absolute Windows path detected."
                )

            # Traversal
            if ".." in parts:
                raise ValueError(
                    "Unsafe ZIP archive: "
                    "path traversal detected."
                )

            target = (
                destination
                / normalized
            ).resolve()

            try:
                target.relative_to(
                    destination
                )
            except ValueError:
                raise ValueError(
                    "Unsafe ZIP archive."
                )

            # Unix symbolic links
            unix_mode = (
                member.external_attr >> 16
            ) & 0xFFFF

            if (
                unix_mode & 0o170000
            ) == 0o120000:
                raise ValueError(
                    "Unsafe ZIP archive: "
                    "symbolic links are not allowed."
                )

        archive.extractall(
            destination
        )


# ============================================================
# Seal folder
# ============================================================

def seal_folder():
    source = filedialog.askdirectory(
        parent=root,
        title="Select folder to seal"
    )

    if not source:
        return

    password = ask_password(
        "Seal folder",
        confirm=True,
        require_strong=True
    )

    if password is None:
        return

    source_path = Path(
        source
    )

    output = filedialog.asksaveasfilename(
        parent=root,
        title="Where should the sealed folder be saved?",
        initialfile=(
            source_path.name
            + ".fencdir"
        ),
        defaultextension=".fencdir",
        filetypes=[
            (
                "FileEnc folders",
                "*.fencdir"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not output:
        return

    output_path = Path(
        output
    )

    if same_path(
        source_path,
        output_path
    ):
        messagebox.showerror(
            APP_NAME,
            "Output cannot be the source folder.",
            parent=root
        )
        return

    if not ask_overwrite(
        output_path
    ):
        return

    def worker():
        zip_temp = None
        encrypted_temp = None

        try:
            set_status(
                "Packing folder...",
                ACCENT
            )

            zip_temp = Path(
                tempfile.mktemp(
                    prefix="fileenc_",
                    suffix=".zip"
                )
            )

            encrypted_temp = output_path.with_name(
                "." + output_path.name + ".tmp"
            )

            folder_to_zip_disk(
                source_path,
                zip_temp
            )

            set_status(
                "Encrypting folder...",
                ACCENT
            )

            aes_encrypt_stream(
                zip_temp,
                encrypted_temp,
                password,
                FOLDER_MAGIC
            )

            # Verify by decrypting the encrypted archive
            verify_zip = Path(
                tempfile.mktemp(
                    prefix="fileenc_verify_",
                    suffix=".zip"
                )
            )

            try:
                set_status(
                    "Verifying folder...",
                    ACCENT
                )

                aes_decrypt_stream(
                    encrypted_temp,
                    verify_zip,
                    password,
                    FOLDER_MAGIC
                )

                with zipfile.ZipFile(
                    verify_zip,
                    "r"
                ) as archive:

                    if len(
                        archive.infolist()
                    ) > MAX_ZIP_ENTRIES:
                        raise ValueError(
                            "Verification ZIP is invalid."
                        )

            finally:
                verify_zip.unlink(
                    missing_ok=True
                )

            os.replace(
                encrypted_temp,
                output_path
            )

            delete_original = messagebox.askyesno(
                "Folder encrypted",
                "The folder was encrypted and verified successfully.\n\n"
                "Delete the original folder?",
                icon="warning",
                parent=root
            )

            if delete_original:
                shutil.rmtree(
                    source_path
                )

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Folder sealed successfully! ✅\n\n"
                    "Algorithm: AES-256-GCM\n"
                    f"Saved to:\n{output_path}",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:
            encrypted_temp.unlink(
                missing_ok=True
            ) if encrypted_temp else None

            def failure():
                set_status(
                    "Seal folder failed",
                    DANGER
                )

                messagebox.showerror(
                    "Seal folder error",
                    str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

        finally:
            if zip_temp:
                zip_temp.unlink(
                    missing_ok=True
                )

            if encrypted_temp:
                encrypted_temp.unlink(
                    missing_ok=True
                )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Seal folder & Replace
# ============================================================

def seal_folder_replace():
    source = filedialog.askdirectory(
        parent=root,
        title="Select folder to seal and replace"
    )

    if not source:
        return

    source_path = Path(
        source
    )

    password = ask_password(
        "Seal Folder & Replace",
        confirm=True,
        require_strong=True
    )

    if password is None:
        return

    output_path = Path(
        str(source_path)
        + ".fencdir"
    )

    if output_path.exists():
        overwrite = messagebox.askyesno(
            APP_NAME,
            f"The encrypted folder already exists:\n\n"
            f"{output_path}\n\n"
            "Overwrite it?",
            parent=root
        )

        if not overwrite:
            return

    confirm_delete = messagebox.askyesno(
        "Confirm Seal & Replace",
        "The original folder will be deleted ONLY "
        "after successful encryption and verification.\n\n"
        f"Original:\n{source_path}\n\n"
        f"Encrypted:\n{output_path}\n\n"
        "Continue?",
        icon="warning",
        parent=root
    )

    if not confirm_delete:
        return

    def worker():
        zip_temp = None
        encrypted_temp = None

        try:
            set_status(
                "Packing folder...",
                ACCENT
            )

            zip_temp = Path(
                tempfile.mktemp(
                    prefix="fileenc_",
                    suffix=".zip"
                )
            )

            encrypted_temp = output_path.with_name(
                "." + output_path.name + ".tmp"
            )

            folder_to_zip_disk(
                source_path,
                zip_temp
            )

            set_status(
                "Encrypting and verifying...",
                ACCENT
            )

            aes_encrypt_stream(
                zip_temp,
                encrypted_temp,
                password,
                FOLDER_MAGIC
            )

            verify_zip = Path(
                tempfile.mktemp(
                    prefix="fileenc_verify_",
                    suffix=".zip"
                )
            )

            try:
                aes_decrypt_stream(
                    encrypted_temp,
                    verify_zip,
                    password,
                    FOLDER_MAGIC
                )

                if not verify_zip.exists():
                    raise ValueError(
                        "Verification failed."
                    )

                with zipfile.ZipFile(
                    verify_zip,
                    "r"
                ) as archive:
                    archive.testzip()

            finally:
                verify_zip.unlink(
                    missing_ok=True
                )

            os.replace(
                encrypted_temp,
                output_path
            )

            shutil.rmtree(
                source_path
            )

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Seal Folder & Replace completed! ✅\n\n"
                    "The encrypted folder was verified.\n"
                    "The original folder was removed.\n\n"
                    f"Created:\n{output_path}",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:

            if encrypted_temp:
                encrypted_temp.unlink(
                    missing_ok=True
                )

            def failure():
                set_status(
                    "Seal & Replace failed",
                    DANGER
                )

                messagebox.showerror(
                    "Seal Folder & Replace error",
                    "The original folder was kept.\n\n"
                    + str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

        finally:
            if zip_temp:
                zip_temp.unlink(
                    missing_ok=True
                )

            if encrypted_temp:
                encrypted_temp.unlink(
                    missing_ok=True
                )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Unseal folder
# ============================================================

def unseal_folder():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select sealed folder",
        filetypes=[
            (
                "FileEnc folders",
                "*.fencdir"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not source:
        return

    password = ask_password(
        "Unseal folder"
    )

    if password is None:
        return

    destination = filedialog.askdirectory(
        parent=root,
        title="Select destination folder"
    )

    if not destination:
        return

    source_path = Path(
        source
    )

    destination_path = Path(
        destination
    )

    if source_path.suffix.lower() == ".fencdir":
        default_name = source_path.stem
    else:
        default_name = (
            source_path.name
            + "_restored"
        )

    output_folder = unique_path(
        destination_path
        / default_name
    )

    def worker():
        temp_zip = None
        temp_folder = None

        try:
            set_status(
                "Decrypting folder...",
                ACCENT
            )

            temp_zip = Path(
                tempfile.mktemp(
                    prefix="fileenc_",
                    suffix=".zip"
                )
            )

            temp_folder = Path(
                tempfile.mkdtemp(
                    prefix="fileenc_restore_"
                )
            )

            decrypt_any_folder_to_zip(
                source_path,
                temp_zip,
                password
            )

            set_status(
                "Checking archive...",
                ACCENT
            )

            secure_extract(
                temp_zip,
                temp_folder
            )

            shutil.move(
                str(temp_folder),
                str(output_folder)
            )

            temp_folder = None

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Folder restored successfully! ✅\n\n"
                    f"Restored to:\n{output_folder}",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:

            def failure():
                set_status(
                    "Unseal failed",
                    DANGER
                )

                messagebox.showerror(
                    "Unseal folder error",
                    str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

        finally:
            if temp_zip:
                temp_zip.unlink(
                    missing_ok=True
                )

            if temp_folder:
                shutil.rmtree(
                    temp_folder,
                    ignore_errors=True
                )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Folder decryption helper
# ============================================================

def decrypt_any_folder_to_zip(
    source,
    output,
    password
):
    with open(
        source,
        "rb"
    ) as file:
        header = file.read(
            32
        )

    if header.startswith(
        FOLDER_MAGIC
    ):
        return aes_decrypt_stream(
            source,
            output,
            password,
            FOLDER_MAGIC
        )

    if header.startswith(
        FOLDER_MAGIC_V2
    ):
        data = Path(
            source
        ).read_bytes()

        decrypted = aes_decrypt_full(
            data,
            password,
            FOLDER_MAGIC_V2
        )

        atomic_write(
            output,
            decrypted
        )

        return len(decrypted)

    if header.startswith(
        OLD_FOLDER_MAGIC
    ):
        data = Path(
            source
        ).read_bytes()

        decrypted = legacy_decrypt_full(
            data,
            password,
            OLD_FOLDER_MAGIC
        )

        atomic_write(
            output,
            decrypted
        )

        return len(decrypted)

    raise ValueError(
        "Unknown FileEnc folder format."
    )


# ============================================================
# Unseal folder & Replace
# ============================================================

def unseal_folder_replace():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select sealed folder to unseal and replace",
        filetypes=[
            (
                "FileEnc folders",
                "*.fencdir"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not source:
        return

    source_path = Path(
        source
    )

    password = ask_password(
        "Unseal Folder & Replace"
    )

    if password is None:
        return

    if source_path.suffix.lower() == ".fencdir":
        output_folder = source_path.with_suffix("")
    else:
        output_folder = Path(
            str(source_path)
            + "_restored"
        )

    if output_folder.exists():
        overwrite = messagebox.askyesno(
            APP_NAME,
            "The restored folder already exists:\n\n"
            f"{output_folder}\n\n"
            "Replace it?",
            parent=root
        )

        if not overwrite:
            return

    confirm_delete = messagebox.askyesno(
        "Confirm Unseal & Replace",
        "The encrypted .fencdir will be deleted ONLY "
        "after successful restoration.\n\n"
        f"Encrypted:\n{source_path}\n\n"
        f"Folder:\n{output_folder}\n\n"
        "Continue?",
        icon="warning",
        parent=root
    )

    if not confirm_delete:
        return

    def worker():
        temp_zip = None
        temp_folder = None

        try:
            set_status(
                "Decrypting folder...",
                ACCENT
            )

            temp_zip = Path(
                tempfile.mktemp(
                    prefix="fileenc_",
                    suffix=".zip"
                )
            )

            temp_folder = Path(
                tempfile.mkdtemp(
                    prefix="fileenc_restore_"
                )
            )

            decrypt_any_folder_to_zip(
                source_path,
                temp_zip,
                password
            )

            set_status(
                "Verifying archive...",
                ACCENT
            )

            secure_extract(
                temp_zip,
                temp_folder
            )

            # Now we know decryption and extraction succeeded.
            if output_folder.exists():
                remove_path(
                    output_folder
                )

            shutil.move(
                str(temp_folder),
                str(output_folder)
            )

            temp_folder = None

            # Only now delete the encrypted source.
            source_path.unlink()

            def success():
                set_status(
                    "Ready",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Unseal Folder & Replace completed! ✅\n\n"
                    f"Restored to:\n{output_folder}\n\n"
                    "The encrypted .fencdir was removed.",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:

            def failure():
                set_status(
                    "Unseal & Replace failed",
                    DANGER
                )

                messagebox.showerror(
                    "Unseal Folder & Replace error",
                    "The encrypted source was kept "
                    "when possible.\n\n"
                    + str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

        finally:
            if temp_zip:
                temp_zip.unlink(
                    missing_ok=True
                )

            if temp_folder:
                shutil.rmtree(
                    temp_folder,
                    ignore_errors=True
                )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# Verify FileEnc
# ============================================================

def verify_fileenc():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select FileEnc file to verify",
        filetypes=[
            (
                "FileEnc files",
                "*.fenc *.fencdir"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not source:
        return

    password = ask_password(
        "Verify FileEnc"
    )

    if password is None:
        return

    source_path = Path(
        source
    )

    def worker():
        try:
            with open(
                source_path,
                "rb"
            ) as file:
                header = file.read(
                    32
                )

            set_status(
                "Verifying...",
                ACCENT
            )

            if header.startswith(
                FILE_MAGIC
            ):
                temp_output = Path(
                    tempfile.mktemp(
                        prefix="fileenc_verify_"
                    )
                )

                try:
                    size = aes_decrypt_stream(
                        source_path,
                        temp_output,
                        password,
                        FILE_MAGIC
                    )
                finally:
                    temp_output.unlink(
                        missing_ok=True
                    )

                kind = "Chunked encrypted file"

            elif header.startswith(
                FOLDER_MAGIC
            ):
                temp_zip = Path(
                    tempfile.mktemp(
                        prefix="fileenc_verify_",
                        suffix=".zip"
                    )
                )

                try:
                    aes_decrypt_stream(
                        source_path,
                        temp_zip,
                        password,
                        FOLDER_MAGIC
                    )

                    with zipfile.ZipFile(
                        temp_zip,
                        "r"
                    ) as archive:
                        if len(
                            archive.infolist()
                        ) > MAX_ZIP_ENTRIES:
                            raise ValueError(
                                "ZIP archive is invalid."
                            )

                        archive.testzip()

                finally:
                    temp_zip.unlink(
                        missing_ok=True
                    )

                kind = "Chunked encrypted folder"

            elif header.startswith(
                FILE_MAGIC_V2
            ):
                data = source_path.read_bytes()

                aes_decrypt_full(
                    data,
                    password,
                    FILE_MAGIC_V2
                )

                kind = "AES-256-GCM full file"

            elif header.startswith(
                FOLDER_MAGIC_V2
            ):
                data = source_path.read_bytes()

                decrypted = aes_decrypt_full(
                    data,
                    password,
                    FOLDER_MAGIC_V2
                )

                with zipfile.ZipFile(
                    io.BytesIO(decrypted),
                    "r"
                ) as archive:
                    archive.testzip()

                kind = "AES-256-GCM full folder"

            elif header.startswith(
                OLD_FILE_MAGIC
            ):
                data = source_path.read_bytes()

                legacy_decrypt_full(
                    data,
                    password,
                    OLD_FILE_MAGIC
                )

                kind = "Legacy Fernet file"

            elif header.startswith(
                OLD_FOLDER_MAGIC
            ):
                data = source_path.read_bytes()

                decrypted = legacy_decrypt_full(
                    data,
                    password,
                    OLD_FOLDER_MAGIC
                )

                with zipfile.ZipFile(
                    io.BytesIO(decrypted),
                    "r"
                ) as archive:
                    archive.testzip()

                kind = "Legacy Fernet folder"

            else:
                raise ValueError(
                    "Unknown FileEnc format."
                )

            def success():
                set_status(
                    "Verification successful",
                    SUCCESS
                )

                messagebox.showinfo(
                    APP_NAME,
                    "Verification successful! ✅\n\n"
                    f"Type: {kind}\n"
                    f"Format: {detect_format(header)}\n\n"
                    "The password is correct and "
                    "the data passed integrity checks.",
                    parent=root
                )

            root.after(
                0,
                success
            )

        except Exception as error:

            def failure():
                set_status(
                    "Verification failed",
                    DANGER
                )

                messagebox.showerror(
                    "Verification failed",
                    str(error),
                    parent=root
                )

            root.after(
                0,
                failure
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# File / Folder Info
# ============================================================

def show_info():
    is_file = messagebox.askyesno(
        "FileEnc Info",
        "YES = File\n"
        "NO = Folder",
        parent=root
    )

    if is_file:
        path = filedialog.askopenfilename(
            parent=root,
            title="Select file"
        )
    else:
        path = filedialog.askdirectory(
            parent=root,
            title="Select folder"
        )

    if not path:
        return

    try:
        target = Path(
            path
        )

        if target.is_file():
            stat = target.stat()

            file_type = "Regular file"

            if target.suffix.lower() in (
                ".fenc",
                ".fencdir"
            ):
                try:
                    with open(
                        target,
                        "rb"
                    ) as file:
                        header = file.read(
                            32
                        )

                    file_type = detect_format(
                        header
                    )

                except OSError:
                    file_type = (
                        "FileEnc file "
                        "(format unavailable)"
                    )

            text = (
                f"Name:\n{target.name}\n\n"
                f"Type:\n{file_type}\n\n"
                f"Size:\n"
                f"{format_size(stat.st_size)}\n\n"
                f"Bytes:\n"
                f"{stat.st_size:,}\n\n"
                f"Path:\n{target}"
            )

        elif target.is_dir():
            total_size = 0
            file_count = 0
            folder_count = 0

            for current_root, directories, files in os.walk(
                target
            ):
                folder_count += len(
                    directories
                )

                file_count += len(
                    files
                )

                for filename in files:
                    try:
                        total_size += Path(
                            current_root,
                            filename
                        ).stat().st_size
                    except OSError:
                        pass

            text = (
                f"Name:\n{target.name}\n\n"
                f"Type:\nFolder\n\n"
                f"Files:\n{file_count}\n\n"
                f"Subfolders:\n{folder_count}\n\n"
                f"Total size:\n"
                f"{format_size(total_size)}\n\n"
                f"Path:\n{target}"
            )

        else:
            raise ValueError(
                "Selected path does not exist."
            )

        messagebox.showinfo(
            "FileEnc Info",
            text,
            parent=root
        )

    except Exception as error:
        messagebox.showerror(
            "Info error",
            str(error),
            parent=root
        )


# ============================================================
# Make EXE
# ============================================================

def make_exe():
    script = filedialog.askopenfilename(
        parent=root,
        title="Select Python file",
        filetypes=[
            (
                "Python files",
                "*.py"
            ),
            (
                "All files",
                "*.*"
            )
        ]
    )

    if not script:
        return

    window = tk.Toplevel(root)

    window.title(
        "Make .exe of..."
    )

    window.configure(
        bg=BG
    )

    window.resizable(
        False,
        False
    )

    window.transient(root)
    window.grab_set()

    center_window(
        window,
        480,
        410
    )

    card = tk.Frame(
        window,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    card.pack(
        fill="both",
        expand=True,
        padx=12,
        pady=12
    )

    tk.Label(
        card,
        text="⚙  Make .exe of...",
        bg=CARD,
        fg=TEXT,
        font=("Segoe UI", 15, "bold")
    ).pack(
        pady=(20, 7)
    )

    tk.Label(
        card,
        text=Path(script).name,
        bg=CARD,
        fg=TEXT_MUTED,
        font=("Segoe UI", 9)
    ).pack(
        pady=(0, 18)
    )

    one_file_var = tk.BooleanVar(
        value=True
    )

    no_console_var = tk.BooleanVar(
        value=False
    )

    tk.Checkbutton(
        card,
        text="One file (.exe)",
        variable=one_file_var,
        bg=CARD,
        fg=TEXT,
        activebackground=CARD,
        activeforeground=TEXT,
        selectcolor=CARD_2,
        highlightthickness=0,
        bd=0,
        font=("Segoe UI", 10),
        anchor="w"
    ).pack(
        fill="x",
        padx=35,
        pady=3
    )

    tk.Checkbutton(
        card,
        text="No console window",
        variable=no_console_var,
        bg=CARD,
        fg=TEXT,
        activebackground=CARD,
        activeforeground=TEXT,
        selectcolor=CARD_2,
        highlightthickness=0,
        bd=0,
        font=("Segoe UI", 10),
        anchor="w"
    ).pack(
        fill="x",
        padx=35,
        pady=3
    )

    build_status = tk.Label(
        card,
        text="Ready.",
        bg=CARD,
        fg=TEXT_MUTED,
        font=("Segoe UI", 9)
    )

    build_status.pack(
        pady=(20, 8)
    )

    progress = ttk.Progressbar(
        card,
        mode="indeterminate",
        length=320
    )

    progress.pack(
        pady=5
    )

    build_button = tk.Button(
        card,
        text="Build EXE",
        bg=ACCENT,
        fg="white",
        activebackground=ACCENT_HOVER,
        activeforeground="white",
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Segoe UI", 10, "bold"),
        padx=28,
        pady=8
    )

    build_button.pack(
        pady=16
    )

    def build():
        one_file = one_file_var.get()
        no_console = no_console_var.get()

        build_button.config(
            state="disabled"
        )

        build_status.config(
            text="Checking PyInstaller..."
        )

        progress.start(10)

        def worker():
            temp_dir = None

            try:
                check = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "PyInstaller",
                        "--version"
                    ],
                    capture_output=True,
                    text=True
                )

                if check.returncode != 0:
                    raise RuntimeError(
                        "PyInstaller is not installed.\n\n"
                        f"Install it with:\n"
                        f"{sys.executable} "
                        f"-m pip install pyinstaller"
                    )

                script_path = Path(
                    script
                )

                dist_path = (
                    script_path.parent
                    / "dist"
                )

                temp_dir = Path(
                    tempfile.mkdtemp(
                        prefix="fileenc_build_"
                    )
                )

                command = [
                    sys.executable,
                    "-m",
                    "PyInstaller",
                    "--clean",
                    "--noconfirm",
                    "--distpath",
                    str(dist_path),
                    "--workpath",
                    str(
                        temp_dir
                        / "build"
                    ),
                    "--specpath",
                    str(
                        temp_dir
                        / "spec"
                    )
                ]

                if one_file:
                    command.append(
                        "--onefile"
                    )

                if no_console:
                    command.append(
                        "--windowed"
                    )

                command.append(
                    str(script_path)
                )

                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    raise RuntimeError(
                        result.stderr.strip()
                        or result.stdout.strip()
                        or "PyInstaller failed."
                    )

                exe_path = (
                    dist_path
                    / (
                        script_path.stem
                        + ".exe"
                    )
                )

                if not exe_path.exists():
                    raise RuntimeError(
                        "EXE was not found after building."
                    )

                def success():
                    progress.stop()

                    build_status.config(
                        text="Build complete! ✅",
                        fg=SUCCESS
                    )

                    messagebox.showinfo(
                        APP_NAME,
                        "EXE created successfully! ✅\n\n"
                        f"{exe_path}",
                        parent=window
                    )

                    window.destroy()

                root.after(
                    0,
                    success
                )

            except Exception as error:

                def failure():
                    progress.stop()

                    build_button.config(
                        state="normal"
                    )

                    build_status.config(
                        text="Build failed.",
                        fg=DANGER
                    )

                    messagebox.showerror(
                        "EXE build error",
                        str(error),
                        parent=window
                    )

                root.after(
                    0,
                    failure
                )

            finally:
                if temp_dir:
                    shutil.rmtree(
                        temp_dir,
                        ignore_errors=True
                    )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    build_button.config(
        command=build
    )


# ============================================================
# Reset App
# ============================================================

def reset_app():
    folder = filedialog.askdirectory(
        parent=root,
        title="Select application's data folder"
    )

    if not folder:
        return

    folder_path = Path(
        folder
    ).resolve()

    # Refuse filesystem root.
    if folder_path.parent == folder_path:
        messagebox.showerror(
            APP_NAME,
            "For safety, FileEnc cannot reset "
            "a filesystem or drive root.",
            parent=root
        )
        return

    first = messagebox.askyesno(
        "Reset app",
        "Everything INSIDE this folder will be deleted:\n\n"
        f"{folder_path}\n\n"
        "The folder itself will remain.\n\n"
        "Continue?",
        icon="warning",
        parent=root
    )

    if not first:
        return

    second = messagebox.askyesno(
        "Final confirmation",
        "Are you REALLY sure?\n\n"
        "Settings, saves and local data may be deleted.",
        icon="warning",
        parent=root
    )

    if not second:
        return

    deleted = 0
    failed = []

    try:
        set_status(
            "Resetting app data...",
            ACCENT
        )

        for item in folder_path.iterdir():

            try:
                remove_path(
                    item
                )

                deleted += 1

            except Exception as error:
                failed.append(
                    f"{item.name}: {error}"
                )

        if failed:
            set_status(
                "Reset partially completed",
                WARNING
            )

            messagebox.showwarning(
                "Reset partially completed",
                f"Deleted: {deleted}\n\n"
                "Could not remove:\n\n"
                + "\n".join(
                    failed[:10]
                ),
                parent=root
            )

        else:
            set_status(
                "Ready",
                SUCCESS
            )

            messagebox.showinfo(
                APP_NAME,
                "App data reset successfully! ✅",
                parent=root
            )

    except Exception as error:
        set_status(
            "Reset failed",
            DANGER
        )

        messagebox.showerror(
            "Reset error",
            str(error),
            parent=root
        )


# ============================================================
# Main Window
# ============================================================

root = tk.Tk()

root.title(
    f"{APP_NAME} {APP_VERSION}"
)

root.geometry(
    "630x900"
)

root.minsize(
    630,
    900
)

root.configure(
    bg=BG
)


# ============================================================
# ttk style
# ============================================================

style = ttk.Style()

try:
    style.theme_use(
        "clam"
    )
except tk.TclError:
    pass

style.configure(
    "TProgressbar",
    troughcolor=BG,
    background=ACCENT,
    bordercolor=BG,
    lightcolor=ACCENT,
    darkcolor=ACCENT
)


# ============================================================
# Header
# ============================================================

header = tk.Frame(
    root,
    bg=BG
)

header.pack(
    fill="x",
    padx=35,
    pady=(28, 10)
)

tk.Label(
    header,
    text="🔐",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI Emoji", 30)
).pack(
    side="left",
    padx=(0, 12)
)

title_frame = tk.Frame(
    header,
    bg=BG
)

title_frame.pack(
    side="left"
)

tk.Label(
    title_frame,
    text=APP_NAME,
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 26, "bold")
).pack(
    anchor="w"
)

tk.Label(
    title_frame,
    text="AES-256-GCM file encryption utility",
    bg=BG,
    fg=TEXT_MUTED,
    font=("Segoe UI", 10)
).pack(
    anchor="w"
)


# ============================================================
# Version
# ============================================================

tk.Label(
    root,
    text=APP_VERSION,
    bg=CARD_2,
    fg=ACCENT,
    font=("Segoe UI", 9, "bold"),
    padx=10,
    pady=5
).pack(
    anchor="e",
    padx=38,
    pady=(0, 12)
)


# ============================================================
# Separator
# ============================================================

tk.Frame(
    root,
    bg=BORDER,
    height=1
).pack(
    fill="x",
    padx=35
)


# ============================================================
# Main card
# ============================================================

main_card = tk.Frame(
    root,
    bg=CARD,
    highlightbackground=BORDER,
    highlightthickness=1
)

main_card.pack(
    fill="both",
    expand=True,
    padx=35,
    pady=20
)


tk.Label(
    main_card,
    text="File operations",
    bg=CARD,
    fg=TEXT,
    font=("Segoe UI", 13, "bold")
).pack(
    anchor="w",
    padx=25,
    pady=(22, 4)
)

tk.Label(
    main_card,
    text="Choose an operation",
    bg=CARD,
    fg=TEXT_MUTED,
    font=("Segoe UI", 9)
).pack(
    anchor="w",
    padx=25,
    pady=(0, 13)
)


# ============================================================
# Button helper
# ============================================================

def add_button(
    parent,
    text,
    command,
    danger=False
):
    normal_bg = (
        "#382027"
        if danger
        else CARD_2
    )

    hover_bg = (
        "#5A2932"
        if danger
        else ACCENT_HOVER
    )

    button = tk.Button(
        parent,
        text=text,
        command=command,
        bg=normal_bg,
        fg=TEXT,
        activebackground=hover_bg,
        activeforeground="white",
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Segoe UI", 10, "bold"),
        anchor="w",
        padx=18,
        pady=8
    )

    button.pack(
        fill="x",
        padx=25,
        pady=2
    )

    def enter(_event):
        button.config(
            bg=hover_bg,
            fg="white"
        )

    def leave(_event):
        button.config(
            bg=normal_bg,
            fg=TEXT
        )

    button.bind(
        "<Enter>",
        enter
    )

    button.bind(
        "<Leave>",
        leave
    )

    return button


# ============================================================
# File operations
# ============================================================

add_button(
    main_card,
    "🔐   Encrypt file...",
    encrypt_file
)

add_button(
    main_card,
    "🔄   Encrypt & Replace...",
    encrypt_replace_file
)

add_button(
    main_card,
    "🔓   Decrypt file...",
    decrypt_file
)

add_button(
    main_card,
    "🔄   Decrypt & Replace...",
    decrypt_replace_file
)


# ============================================================
# Folder operations
# ============================================================

add_button(
    main_card,
    "📁   Seal folder...",
    seal_folder
)

add_button(
    main_card,
    "🔄   Seal folder & Replace...",
    seal_folder_replace
)

add_button(
    main_card,
    "📂   Unseal folder...",
    unseal_folder
)

add_button(
    main_card,
    "🔄   Unseal folder & Replace...",
    unseal_folder_replace
)


# ============================================================
# Utilities
# ============================================================

add_button(
    main_card,
    "✅   Verify FileEnc...",
    verify_fileenc
)

add_button(
    main_card,
    "ℹ️   File / Folder info...",
    show_info
)

add_button(
    main_card,
    "⚙️   Make .exe of...",
    make_exe
)

add_button(
    main_card,
    "🧹   Reset app...",
    reset_app,
    danger=True
)


# ============================================================
# Status
# ============================================================

status_frame = tk.Frame(
    main_card,
    bg="#12161D",
    highlightbackground=BORDER,
    highlightthickness=1
)

status_frame.pack(
    fill="x",
    padx=25,
    pady=(16, 15)
)

tk.Label(
    status_frame,
    text="STATUS",
    bg="#12161D",
    fg=TEXT_MUTED,
    font=("Segoe UI", 8, "bold")
).pack(
    anchor="w",
    padx=12,
    pady=(9, 0)
)

status_label = tk.Label(
    status_frame,
    text="Ready",
    bg="#12161D",
    fg=SUCCESS,
    font=("Segoe UI", 10, "bold")
)

status_label.pack(
    anchor="w",
    padx=12,
    pady=(2, 9)
)


# ============================================================
# Security panel
# ============================================================

security_frame = tk.Frame(
    main_card,
    bg="#12161D",
    highlightbackground=BORDER,
    highlightthickness=1
)

security_frame.pack(
    fill="x",
    padx=25,
    pady=(0, 20)
)

tk.Label(
    security_frame,
    text="SECURITY",
    bg="#12161D",
    fg=TEXT_MUTED,
    font=("Segoe UI", 8, "bold")
).pack(
    anchor="w",
    padx=12,
    pady=(9, 0)
)

tk.Label(
    security_frame,
    text=(
        "AES-256-GCM  •  PBKDF2-HMAC-SHA256  •  "
        "Random salt + nonce"
    ),
    bg="#12161D",
    fg=SUCCESS,
    font=("Segoe UI", 9, "bold")
).pack(
    anchor="w",
    padx=12,
    pady=(2, 3)
)

tk.Label(
    security_frame,
    text=(
        f"PBKDF2 iterations: "
        f"{PBKDF2_ITERATIONS:,}  •  "
        f"Chunk: {format_size(CHUNK_SIZE)}"
    ),
    bg="#12161D",
    fg=TEXT_MUTED,
    font=("Segoe UI", 8)
).pack(
    anchor="w",
    padx=12,
    pady=(0, 3)
)

tk.Label(
    security_frame,
    text="No Registry  •  No Explorer integration",
    bg="#12161D",
    fg=TEXT_MUTED,
    font=("Segoe UI", 8)
).pack(
    anchor="w",
    padx=12,
    pady=(0, 9)
)


# ============================================================
# Footer
# ============================================================

footer = tk.Frame(
    root,
    bg=BG
)

footer.pack(
    fill="x",
    padx=35,
    pady=(0, 18)
)

tk.Label(
    footer,
    text=f"{APP_NAME} {APP_VERSION}",
    bg=BG,
    fg=TEXT_MUTED,
    font=("Segoe UI", 8)
).pack(
    side="left"
)

tk.Label(
    footer,
    text="No ПКМ 😎",
    bg=BG,
    fg=TEXT_MUTED,
    font=("Segoe UI", 8)
).pack(
    side="right"
)


# ============================================================
# Run
# ============================================================

root.mainloop()
