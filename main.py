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
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================
# FileEnc 0.04V
# ============================================================

APP_NAME = "FileEnc"
APP_VERSION = "0.04V"

# ------------------------------------------------------------
# Old formats
# ------------------------------------------------------------

OLD_FILE_MAGIC = b"FILEENC01"
OLD_FOLDER_MAGIC = b"FILEDIR01"

# ------------------------------------------------------------
# New AES-256-GCM formats
# ------------------------------------------------------------

FILE_MAGIC = b"FILEENC02"
FOLDER_MAGIC = b"FILEDIR02"

SALT_SIZE = 16
NONCE_SIZE = 12

AES_KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000

MIN_PASSWORD_LENGTH = 8

MAX_ZIP_ENTRIES = 100_000


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
    status_label.config(
        text=text,
        fg=color
    )

    root.update_idletasks()


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
        return os.path.abspath(a) == os.path.abspath(b)


def atomic_write(path, data):
    """
    Write data to a temporary file and then replace
    the destination.

    This helps avoid incomplete output files.
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

            temp_path = Path(temp.name)

            temp.write(data)
            temp.flush()
            os.fsync(temp.fileno())

        os.replace(
            temp_path,
            path
        )

    except Exception:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass

        raise


def ask_overwrite(path):
    path = Path(path)

    if not path.exists():
        return True

    return messagebox.askyesno(
        APP_NAME,
        f"This file already exists:\n\n"
        f"{path}\n\n"
        "Overwrite it?",
        parent=root
    )


# ============================================================
# Password strength
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
        character.islower()
        for character in password
    ):
        score += 1

    if any(
        character.isupper()
        for character in password
    ):
        score += 1

    if any(
        character.isdigit()
        for character in password
    ):
        score += 1

    if any(
        character in string.punctuation
        for character in password
    ):
        score += 1

    if score <= 2:
        return "Weak", DANGER

    if score <= 4:
        return "Medium", WARNING

    return "Strong", SUCCESS


def generate_password(length=20):
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
    window.configure(
        bg=BG
    )

    window.resizable(
        False,
        False
    )

    window.transient(root)
    window.grab_set()

    height = 380 if confirm else 330

    center_window(
        window,
        470,
        height
    )

    result = {
        "password": None
    }

    # --------------------------------------------------------
    # Card
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Title
    # --------------------------------------------------------

    tk.Label(
        card,
        text=title,
        bg=CARD,
        fg=TEXT,
        font=("Segoe UI", 15, "bold")
    ).pack(
        pady=(18, 15)
    )

    # --------------------------------------------------------
    # Password label
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Password entry
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Strength
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Confirm password
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Options
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Buttons
    # --------------------------------------------------------

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
            strength, _ = password_strength(
                password
            )

            if len(password) < MIN_PASSWORD_LENGTH:
                messagebox.showwarning(
                    APP_NAME,
                    f"Password must contain at least "
                    f"{MIN_PASSWORD_LENGTH} characters.",
                    parent=window
                )
                password_entry.focus_set()
                return

            if strength == "Weak":
                use_stronger = messagebox.askyesno(
                    APP_NAME,
                    "This password is weak.\n\n"
                    "Use a stronger password?",
                    parent=window
                )

                if use_stronger:
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
# AES-256-GCM
# ============================================================

def aes_encrypt(data, password, magic):
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

    encrypted = AESGCM(
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
        + encrypted
    )


def aes_decrypt(
    data,
    password,
    magic
):
    if not data.startswith(
        magic
    ):
        raise ValueError(
            "Invalid FileEnc AES format."
        )

    salt_start = len(magic)
    salt_end = salt_start + SALT_SIZE

    nonce_start = salt_end
    nonce_end = nonce_start + NONCE_SIZE

    if len(data) <= nonce_end:
        raise ValueError(
            "FileEnc data is incomplete or corrupted."
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
            "FileEnc file."
        )


# ============================================================
# Legacy Fernet support
# ============================================================

def legacy_decrypt(
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
    salt_end = salt_start + SALT_SIZE

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


def decrypt_any(
    data,
    password,
    new_magic,
    old_magic
):
    if data.startswith(
        new_magic
    ):
        return aes_decrypt(
            data,
            password,
            new_magic
        )

    if data.startswith(
        old_magic
    ):
        return legacy_decrypt(
            data,
            password,
            old_magic
        )

    raise ValueError(
        "Unknown FileEnc format."
    )


def detect_format(data):
    if data.startswith(
        FILE_MAGIC
    ):
        return "AES-256-GCM file"

    if data.startswith(
        FOLDER_MAGIC
    ):
        return "AES-256-GCM folder"

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

    try:
        set_status(
            "Encrypting with AES-256-GCM...",
            ACCENT
        )

        with open(
            source_path,
            "rb"
        ) as file:
            original = file.read()

        encrypted = aes_encrypt(
            original,
            password,
            FILE_MAGIC
        )

        atomic_write(
            output_path,
            encrypted
        )

        # Verify result
        with open(
            output_path,
            "rb"
        ) as file:
            saved = file.read()

        verified = aes_decrypt(
            saved,
            password,
            FILE_MAGIC
        )

        if verified != original:
            raise ValueError(
                "Verification failed."
            )

        set_status(
            "Ready",
            SUCCESS
        )

        messagebox.showinfo(
            APP_NAME,
            "Encryption successful! ✅\n\n"
            "Algorithm: AES-256-GCM\n\n"
            f"Saved to:\n{output_path}",
            parent=root
        )

    except Exception as error:
        set_status(
            "Encryption failed",
            DANGER
        )

        messagebox.showerror(
            "Encryption error",
            str(error),
            parent=root
        )


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
        "after successful encryption and verification.\n\n"
        f"Original:\n{source_path}\n\n"
        f"Encrypted:\n{output_path}\n\n"
        "Continue?",
        icon="warning",
        parent=root
    )

    if not confirm_delete:
        return

    try:
        set_status(
            "Encrypting and verifying...",
            ACCENT
        )

        with open(
            source_path,
            "rb"
        ) as file:
            original = file.read()

        encrypted = aes_encrypt(
            original,
            password,
            FILE_MAGIC
        )

        atomic_write(
            output_path,
            encrypted
        )

        with open(
            output_path,
            "rb"
        ) as file:
            saved = file.read()

        verified = aes_decrypt(
            saved,
            password,
            FILE_MAGIC
        )

        if verified != original:
            raise ValueError(
                "Verification failed."
            )

        source_path.unlink()

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

    except Exception as error:
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

    if not ask_overwrite(
        output_path
    ):
        return

    try:
        set_status(
            "Decrypting...",
            ACCENT
        )

        with open(
            source_path,
            "rb"
        ) as file:
            encrypted = file.read()

        decrypted = decrypt_any(
            encrypted,
            password,
            FILE_MAGIC,
            OLD_FILE_MAGIC
        )

        atomic_write(
            output_path,
            decrypted
        )

        set_status(
            "Ready",
            SUCCESS
        )

        messagebox.showinfo(
            APP_NAME,
            "Decryption successful! ✅\n\n"
            f"Format: {detect_format(encrypted)}\n\n"
            f"Saved to:\n{output_path}",
            parent=root
        )

    except Exception as error:
        set_status(
            "Decryption failed",
            DANGER
        )

        messagebox.showerror(
            "Decryption error",
            str(error),
            parent=root
        )


# ============================================================
# Decrypt & Replace
# ============================================================

def decrypt_replace_file():
    source = filedialog.askopenfilename(
        parent=root,
        title="Select encrypted file"
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

    if not ask_overwrite(
        output_path
    ):
        return

    confirm_delete = messagebox.askyesno(
        "Confirm Decrypt & Replace",
        "The encrypted original will be deleted ONLY "
        "after successful decryption and verification.\n\n"
        f"Encrypted:\n{source_path}\n\n"
        f"Decrypted:\n{output_path}\n\n"
        "Continue?",
        icon="warning",
        parent=root
    )

    if not confirm_delete:
        return

    try:
        set_status(
            "Decrypting and verifying...",
            ACCENT
        )

        with open(
            source_path,
            "rb"
        ) as file:
            encrypted = file.read()

        decrypted = decrypt_any(
            encrypted,
            password,
            FILE_MAGIC,
            OLD_FILE_MAGIC
        )

        atomic_write(
            output_path,
            decrypted
        )

        with open(
            output_path,
            "rb"
        ) as file:
            written = file.read()

        if written != decrypted:
            raise ValueError(
                "Verification failed."
            )

        source_path.unlink()

        set_status(
            "Ready",
            SUCCESS
        )

        messagebox.showinfo(
            APP_NAME,
            "Decrypt & Replace completed! ✅\n\n"
            "The decrypted file was verified.\n"
            "The encrypted original was removed.",
            parent=root
        )

    except Exception as error:
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


# ============================================================
# Folder -> ZIP
# ============================================================

def folder_to_zip(folder):
    memory = io.BytesIO()

    base = Path(
        folder
    )

    with zipfile.ZipFile(
        memory,
        "w",
        zipfile.ZIP_DEFLATED
    ) as archive:

        for current_root, directories, files in os.walk(
            folder
        ):
            current_root = Path(
                current_root
            )

            # Preserve empty directories
            for directory in directories:
                directory_path = (
                    current_root
                    / directory
                )

                try:
                    empty = not any(
                        directory_path.iterdir()
                    )
                except OSError:
                    empty = False

                if empty:
                    relative = (
                        directory_path.relative_to(
                            base
                        )
                    )

                    archive.writestr(
                        str(relative).replace(
                            "\\",
                            "/"
                        ) + "/",
                        b""
                    )

            # Files
            for filename in files:
                file_path = (
                    current_root
                    / filename
                )

                relative = (
                    file_path.relative_to(
                        base
                    )
                )

                archive.write(
                    file_path,
                    str(relative).replace(
                        "\\",
                        "/"
                    )
                )

    return memory.getvalue()


# ============================================================
# Secure ZIP extraction
# ============================================================

def secure_extract(
    zip_data,
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
        io.BytesIO(zip_data),
        "r"
    ) as archive:

        members = archive.infolist()

        if len(members) > MAX_ZIP_ENTRIES:
            raise ValueError(
                "ZIP archive contains too many entries."
            )

        seen = set()

        for member in members:

            normalized = member.filename.replace(
                "\\",
                "/"
            )

            # Duplicate path
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

            # Absolute path
            if (
                normalized.startswith("/")
                or (
                    parts
                    and ":" in parts[0]
                )
            ):
                raise ValueError(
                    "Unsafe ZIP archive: "
                    "absolute path detected."
                )

            # Directory traversal
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

            # Symbolic link check
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

    source_path = Path(
        source
    )

    password = ask_password(
        "Seal folder",
        confirm=True,
        require_strong=True
    )

    if password is None:
        return

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

    try:
        set_status(
            "Packing folder...",
            ACCENT
        )

        zip_data = folder_to_zip(
            source
        )

        set_status(
            "Encrypting with AES-256-GCM...",
            ACCENT
        )

        encrypted = aes_encrypt(
            zip_data,
            password,
            FOLDER_MAGIC
        )

        atomic_write(
            output_path,
            encrypted
        )

        # Verify
        with open(
            output_path,
            "rb"
        ) as file:
            saved = file.read()

        verified = aes_decrypt(
            saved,
            password,
            FOLDER_MAGIC
        )

        if verified != zip_data:
            raise ValueError(
                "Folder verification failed."
            )

        set_status(
            "Ready",
            SUCCESS
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
                source
            )

        messagebox.showinfo(
            APP_NAME,
            "Folder sealed successfully! ✅\n\n"
            "Algorithm: AES-256-GCM\n\n"
            f"Saved to:\n{output_path}",
            parent=root
        )

    except Exception as error:
        set_status(
            "Folder encryption failed",
            DANGER
        )

        messagebox.showerror(
            "Seal folder error",
            str(error),
            parent=root
        )


# ============================================================
# Seal folder and replace
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
            f"This encrypted folder already exists:\n\n"
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

    try:
        set_status(
            "Packing folder...",
            ACCENT
        )

        zip_data = folder_to_zip(
            source_path
        )

        set_status(
            "Encrypting with AES-256-GCM...",
            ACCENT
        )

        encrypted = aes_encrypt(
            zip_data,
            password,
            FOLDER_MAGIC
        )

        atomic_write(
            output_path,
            encrypted
        )

        set_status(
            "Verifying encrypted folder...",
            ACCENT
        )

        with open(
            output_path,
            "rb"
        ) as file:
            saved = file.read()

        verified = aes_decrypt(
            saved,
            password,
            FOLDER_MAGIC
        )

        if verified != zip_data:
            raise ValueError(
                "Verification failed."
            )

        shutil.rmtree(
            source_path
        )

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

    except Exception as error:
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

    source_path = Path(
        source
    )

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

    try:
        set_status(
            "Decrypting folder...",
            ACCENT
        )

        with open(
            source_path,
            "rb"
        ) as file:
            encrypted = file.read()

        zip_data = decrypt_any(
            encrypted,
            password,
            FOLDER_MAGIC,
            OLD_FOLDER_MAGIC
        )

        set_status(
            "Restoring folder...",
            ACCENT
        )

        temp_folder = Path(
            tempfile.mkdtemp(
                prefix="fileenc_unseal_"
            )
        )

        try:
            secure_extract(
                zip_data,
                temp_folder
            )

            shutil.move(
                str(temp_folder),
                str(output_folder)
            )

            temp_folder = None

        finally:
            if temp_folder is not None:
                shutil.rmtree(
                    temp_folder,
                    ignore_errors=True
                )

        set_status(
            "Ready",
            SUCCESS
        )

        messagebox.showinfo(
            APP_NAME,
            "Folder restored successfully! ✅\n\n"
            f"Format: {detect_format(encrypted)}\n\n"
            f"Restored to:\n{output_folder}",
            parent=root
        )

    except Exception as error:
        set_status(
            "Folder decryption failed",
            DANGER
        )

        messagebox.showerror(
            "Unseal folder error",
            str(error),
            parent=root
        )


# ============================================================
# Unseal folder and replace
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

    # --------------------------------------------------------
    # The output may already exist
    # --------------------------------------------------------

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

    temp_folder = None

    try:
        set_status(
            "Reading encrypted folder...",
            ACCENT
        )

        with open(
            source_path,
            "rb"
        ) as file:
            encrypted = file.read()

        set_status(
            "Decrypting with AES-256-GCM...",
            ACCENT
        )

        zip_data = decrypt_any(
            encrypted,
            password,
            FOLDER_MAGIC,
            OLD_FOLDER_MAGIC
        )

        set_status(
            "Restoring folder...",
            ACCENT
        )

        temp_folder = Path(
            tempfile.mkdtemp(
                prefix="fileenc_unseal_"
            )
        )

        secure_extract(
            zip_data,
            temp_folder
        )

        # If an old output exists, remove it now,
        # but ONLY after successful decryption.
        if output_folder.exists():
            if output_folder.is_dir():
                shutil.rmtree(
                    output_folder
                )
            else:
                output_folder.unlink()

        shutil.move(
            str(temp_folder),
            str(output_folder)
        )

        temp_folder = None

        # The encrypted file is deleted only after
        # the restored folder has been moved successfully.
        source_path.unlink()

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

    except Exception as error:
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

    finally:
        if temp_folder is not None:
            shutil.rmtree(
                temp_folder,
                ignore_errors=True
            )


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

    try:
        set_status(
            "Verifying FileEnc data...",
            ACCENT
        )

        with open(
            source_path,
            "rb"
        ) as file:
            data = file.read()

        if data.startswith(
            FILE_MAGIC
        ):
            aes_decrypt(
                data,
                password,
                FILE_MAGIC
            )

            kind = "AES-256-GCM encrypted file"

        elif data.startswith(
            FOLDER_MAGIC
        ):
            aes_decrypt(
                data,
                password,
                FOLDER_MAGIC
            )

            kind = "AES-256-GCM encrypted folder"

        elif data.startswith(
            OLD_FILE_MAGIC
        ):
            legacy_decrypt(
                data,
                password,
                OLD_FILE_MAGIC
            )

            kind = "Legacy encrypted file"

        elif data.startswith(
            OLD_FOLDER_MAGIC
        ):
            legacy_decrypt(
                data,
                password,
                OLD_FOLDER_MAGIC
            )

            kind = "Legacy encrypted folder"

        else:
            raise ValueError(
                "Unknown FileEnc format."
            )

        set_status(
            "Verification successful",
            SUCCESS
        )

        messagebox.showinfo(
            APP_NAME,
            "Verification successful! ✅\n\n"
            f"Type: {kind}\n"
            f"Format: {detect_format(data)}\n\n"
            "The password is correct and the "
            "encrypted data passed integrity verification.",
            parent=root
        )

    except Exception as error:
        set_status(
            "Verification failed",
            DANGER
        )

        messagebox.showerror(
            "Verification failed",
            str(error),
            parent=root
        )


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
                            64
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
            files_count = 0
            folders_count = 0

            for current_root, directories, files in os.walk(
                target
            ):
                folders_count += len(
                    directories
                )

                files_count += len(
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
                f"Files:\n{files_count}\n\n"
                f"Subfolders:\n{folders_count}\n\n"
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

    status = tk.Label(
        card,
        text="Ready.",
        bg=CARD,
        fg=TEXT_MUTED,
        font=("Segoe UI", 9)
    )

    status.pack(
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
        # Tkinter variables are read BEFORE
        # entering the worker thread.
        one_file = one_file_var.get()
        no_console = no_console_var.get()

        build_button.config(
            state="disabled"
        )

        status.config(
            text="Checking PyInstaller...",
            fg=TEXT_MUTED
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
                        "Install it with:\n"
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

                    status.config(
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

                def failed():
                    progress.stop()

                    build_button.config(
                        state="normal"
                    )

                    status.config(
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
                    failed
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

    # Safety: don't allow filesystem root.
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
                if item.is_dir():
                    shutil.rmtree(
                        item
                    )
                else:
                    item.unlink()

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
# Main window
# ============================================================

root = tk.Tk()

root.title(
    f"{APP_NAME} {APP_VERSION}"
)

root.geometry(
    "610x850"
)

root.minsize(
    610,
    850
)

root.configure(
    bg=BG
)


# ============================================================
# ttk
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
    text="AES-256-GCM encryption utility",
    bg=BG,
    fg=TEXT_MUTED,
    font=("Segoe UI", 10)
).pack(
    anchor="w"
)


# ============================================================
# Version badge
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
# Main Card
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
    pady=(22, 5)
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
    pady=(0, 15)
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
# File buttons
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
# Folder buttons
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
# Utility buttons
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
# Status panel
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
    pady=(18, 15)
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
        f"PBKDF2 iterations: {PBKDF2_ITERATIONS:,}"
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
    text=(
        "No Registry • No Explorer integration"
    ),
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
# Start
# ============================================================

root.mainloop()