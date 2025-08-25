# main_firebase.py
import os
import subprocess
import smtplib
import base64
import mimetypes
import tempfile
import time
import wave
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from email.message import EmailMessage
from cryptography.fernet import Fernet, InvalidToken
from pydub import AudioSegment
import pygame
import firebase_admin
from firebase_admin import credentials, firestore
from PIL import Image, ImageTk
import sys

# ----------------------------
# Configuration / Constants
# ----------------------------
ICON_FILES = {
    "lock": "lock.png",
    "folder": "folder.png",
    "music": "music.png",
    "app": "logo.png"
}
BASE64_ICON_FALLBACK = 'iVBORw0KGgoAAAANSUhEUgAAAyEAAAAFrCAYAAADGsobQAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQU='

DEFAULT_SECURE_FOLDER_NAME = "SteganographyData"
DELIMITER = "###ENCRYPTED_END###"

# ----------------------------
# Firebase initialization
# ----------------------------
try:
    cred = credentials.Certificate("firebase-key.json")
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print("Warning: Could not initialize Firebase. Make sure firebase-key.json exists and is valid.")
    db = None

# ----------------------------
# Utility functions: folder hide/unhide
# ----------------------------
def hide_file(path):
    """Hide a file or folder. Works on Windows (attrib) or prefixes '.' on Unix-like systems."""
    try:
        if os.name == "nt":
            subprocess.call(["attrib", "+h", path])
        else:
            dirn = os.path.dirname(path)
            base = os.path.basename(path)
            if not base.startswith('.'):
                os.rename(path, os.path.join(dirn, '.' + base))
    except Exception as e:
        print(f"Warning: Could not hide {path}: {e}")

def unhide_file(path):
    """Unhide a file or folder."""
    try:
        if os.name == "nt":
            subprocess.call(["attrib", "-h", path])
        else:
            dirn = os.path.dirname(path)
            base = os.path.basename(path)
            if base.startswith('.'):
                os.rename(path, os.path.join(dirn, base[1:]))
    except Exception as e:
        print(f"Warning: Could not unhide {path}: {e}")

# ----------------------------
# Firebase user helpers
# ----------------------------
def create_user(username, password):
    """Create user in Firestore with PBKDF2 hashed password."""
    if db is None:
        raise RuntimeError("Firebase not initialized.")
    salt = os.urandom(16)
    iterations = 200000
    pass_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations).hex()
    db.collection("users").document(username).set({
        "pass_hash": pass_hash,
        "salt": salt.hex(),
        "iterations": iterations
    })

def verify_user(username, password):
    """Verify user credentials against Firestore."""
    if db is None:
        return False
    doc = db.collection("users").document(username).get()
    if not doc.exists:
        return False
    data = doc.to_dict()
    salt = bytes.fromhex(data["salt"])
    test_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, data["iterations"]).hex()
    return test_hash == data["pass_hash"]

# ----------------------------
# Main App Classes
# ----------------------------
class HideTextWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent.root)
        self.window.title("Hide Text / File")
        self.window.geometry("660x720")
        self.window.configure(bg='#2b2b2b')

        # Variables
        self.audio_file_path = tk.StringVar()
        self.message_text = tk.StringVar()
        self.file_to_hide_path = tk.StringVar()
        self.sender_email = tk.StringVar()
        self.smtp_password = tk.StringVar()
        self.receiver_email = tk.StringVar()
        self.send_email_var = tk.BooleanVar(value=False)
        self.custom_password = tk.StringVar()
        self.hide_type = tk.StringVar(value="text")

        # Init pygame
        try:
            pygame.mixer.init()
        except:
            pass

        self.create_widgets()

    def create_widgets(self):
        main = ttk.Frame(self.window)
        main.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        # Audio selection
        ttk.Label(main, text="Audio file (carrier):").grid(row=0, column=0, sticky=tk.W, pady=6)
        ttk.Entry(main, textvariable=self.audio_file_path, width=48).grid(row=0, column=1, padx=6)
        ttk.Button(main, text="Browse", command=self.browse_audio_file).grid(row=0, column=2, padx=6)
        ttk.Button(main, text="▶ Play", command=self.play_audio).grid(row=0, column=3, padx=6)

        # Hide type
        hf = ttk.LabelFrame(main, text="What to hide")
        hf.grid(row=1, column=0, columnspan=4, sticky="ew", pady=10)
        ttk.Radiobutton(hf, text="Text Message", variable=self.hide_type, value="text", command=self.toggle_hide_type).grid(row=0, column=0, padx=10, pady=6)
        ttk.Radiobutton(hf, text="File", variable=self.hide_type, value="file", command=self.toggle_hide_type).grid(row=0, column=1, padx=10, pady=6)

        # Text message frame
        self.text_frame = ttk.LabelFrame(main, text="Message")
        self.text_frame.grid(row=2, column=0, columnspan=4, sticky="ew", pady=10)
        self.msg_box = scrolledtext.ScrolledText(self.text_frame, width=70, height=6)
        self.msg_box.pack(padx=8, pady=8)

        # File frame
        self.file_frame = ttk.LabelFrame(main, text="File to hide")
        self.file_frame.grid(row=3, column=0, columnspan=4, sticky="ew", pady=10)
        ttk.Label(self.file_frame, text="File path:").grid(row=0, column=0, sticky=tk.W, padx=6, pady=6)
        ttk.Entry(self.file_frame, textvariable=self.file_to_hide_path, width=48).grid(row=0, column=1, padx=6)
        ttk.Button(self.file_frame, text="Browse", command=self.browse_file_to_hide).grid(row=0, column=2, padx=6)
        self.file_frame.grid_remove()

        # Password
        pwf = ttk.LabelFrame(main, text="Password Settings")
        pwf.grid(row=4, column=0, columnspan=4, sticky="ew", pady=10)
        ttk.Label(pwf, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=6, pady=6)
        ttk.Entry(pwf, textvariable=self.custom_password, show="*", width=36).grid(row=0, column=1, padx=6)

        # Email checkbox and fields
        ttk.Checkbutton(main, text="Send via Email (attach encoded audio)", variable=self.send_email_var, command=self.toggle_email_fields).grid(row=5, column=0, columnspan=4, pady=8)
        self.email_frame = ttk.LabelFrame(main, text="Email Settings")
        self.email_frame.grid(row=6, column=0, columnspan=4, sticky="ew", pady=10)
        ttk.Label(self.email_frame, text="Sender (Gmail):").grid(row=0, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Entry(self.email_frame, textvariable=self.sender_email, width=36).grid(row=0, column=1, padx=6)
        ttk.Label(self.email_frame, text="App Password:").grid(row=1, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Entry(self.email_frame, textvariable=self.smtp_password, show="*", width=36).grid(row=1, column=1, padx=6)
        ttk.Label(self.email_frame, text="Receiver:").grid(row=2, column=0, padx=6, pady=6, sticky=tk.W)
        ttk.Entry(self.email_frame, textvariable=self.receiver_email, width=36).grid(row=2, column=1, padx=6)
        self.toggle_email_fields()

        # Action buttons
        buttons = ttk.Frame(main)
        buttons.grid(row=7, column=0, columnspan=4, pady=16)
        ttk.Button(buttons, text="Hide Data", command=self.hide_data).grid(row=0, column=0, padx=8)
        ttk.Button(buttons, text="Test Latest Encoded Audio", command=self.test_encoded_audio).grid(row=0, column=1, padx=8)

    def toggle_hide_type(self):
        if self.hide_type.get() == "text":
            self.text_frame.grid()
            self.file_frame.grid_remove()
        else:
            self.text_frame.grid_remove()
            self.file_frame.grid()

    def toggle_email_fields(self):
        state = "normal" if self.send_email_var.get() else "disabled"
        for widget in self.email_frame.winfo_children():
            try:
                widget.configure(state=state)
            except:
                pass

    def browse_audio_file(self):
        fn = filedialog.askopenfilename(title="Select audio file", filetypes=[("Audio", "*.wav *.mp3 *.flac *.aac"), ("All files","*.*")])
        if fn:
            self.audio_file_path.set(fn)

    def browse_file_to_hide(self):
        fn = filedialog.askopenfilename(title="Select file to hide", filetypes=[("All files","*.*")])
        if fn:
            self.file_to_hide_path.set(fn)

    def play_audio(self):
        if not self.audio_file_path.get():
            messagebox.showerror("Error", "Select an audio file first")
            return
        try:
            pygame.mixer.music.load(self.audio_file_path.get())
            pygame.mixer.music.play()
            messagebox.showinfo("Playing", "Audio is playing. Click OK to stop.")
            pygame.mixer.music.stop()
        except Exception as e:
            messagebox.showerror("Error", f"Cannot play audio: {e}")

    def get_secure_folder(self):
        # Prefer Documents, fallback to Desktop, else temp
        possible = [os.path.join(os.path.expanduser("~"), "Documents"),
                    os.path.join(os.path.expanduser("~"), "Desktop"),
                    tempfile.gettempdir()]
        for base in possible:
            if base and os.path.exists(base) and os.access(base, os.W_OK):
                folder = os.path.join(base, DEFAULT_SECURE_FOLDER_NAME)
                os.makedirs(folder, exist_ok=True)
                return folder
        # Last resort
        folder = os.path.join(tempfile.gettempdir(), DEFAULT_SECURE_FOLDER_NAME)
        os.makedirs(folder, exist_ok=True)
        return folder

    def encrypt_data(self, data_bytes, password):
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        key = base64.urlsafe_b64encode(key[:32])
        f = Fernet(key)
        return salt + f.encrypt(data_bytes)

    def convert_to_wav(self, input_file, out_path):
        # If already wav, copy to out_path
        if input_file.lower().endswith('.wav'):
            # if input and out path same, just return input_file
            return input_file
        try:
            audio = AudioSegment.from_file(input_file)
            audio.export(out_path, format="wav")
            return out_path
        except Exception as e:
            # warn user and try to proceed (we prefer WAV though)
            messagebox.showwarning("Conversion Warning", f"Could not convert to WAV automatically: {e}\nTry using a WAV file for best results.")
            return input_file

    def send_email_with_attachment(self, attachment_path, data_type, original_filename, password):
        try:
            sender = self.sender_email.get().strip()
            app_pass = self.smtp_password.get().strip()
            receiver = self.receiver_email.get().strip()
            if not (sender and app_pass and receiver):
                messagebox.showerror("Email Error", "Email fields incomplete")
                return False

            msg = EmailMessage()
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = "Encoded Audio - Steganography"
            body = f"An encoded audio file is attached.\n\nType: {data_type}\nFilename: {original_filename}\nPassword: {password}\n"
            msg.set_content(body)

            with open(attachment_path, 'rb') as f:
                maintype, subtype = (mimetypes.guess_type(attachment_path)[0] or "application/octet-stream").split("/", 1)
                msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=os.path.basename(attachment_path))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                s.login(sender, app_pass)
                s.send_message(msg)
            return True
        except Exception as e:
            messagebox.showerror("Email Error", f"Failed to send email: {e}")
            return False

    def hide_data(self):
        try:
            audio_in = self.audio_file_path.get().strip()
            if not audio_in:
                messagebox.showerror("Error", "Select audio file")
                return
            password = self.custom_password.get().strip()
            if not password:
                messagebox.showerror("Error", "Enter password")
                return

            # Prepare data to hide
            if self.hide_type.get() == "text":
                text = self.msg_box.get(1.0, tk.END).strip()
                if not text:
                    messagebox.showerror("Error", "Enter text to hide")
                    return
                header = f"TYPE:TEXT\n".encode()
                payload = header + text.encode()
                original_filename = None
                data_type = "text"
            else:
                filep = self.file_to_hide_path.get().strip()
                if not filep or not os.path.exists(filep):
                    messagebox.showerror("Error", "Select valid file to hide")
                    return
                with open(filep, 'rb') as f:
                    file_bytes = f.read()
                original_filename = os.path.basename(filep)
                header = f"TYPE:FILE\nNAME:{original_filename}\n".encode()
                payload = header + file_bytes
                data_type = "file"

            # Convert carrier to WAV (if possible)
            secure_folder = self.get_secure_folder()
            name, ext = os.path.splitext(os.path.basename(audio_in))
            timestamp = int(time.time())
            output_name = f"{name}_encoded_{timestamp}.wav"
            output_path = os.path.join(secure_folder, output_name)

            if not audio_in.lower().endswith('.wav'):
                converted_path = os.path.join(secure_folder, f"{name}_converted_{timestamp}.wav")
                carrier = self.convert_to_wav(audio_in, converted_path)
            else:
                carrier = audio_in

            # Encrypt payload
            encrypted = self.encrypt_data(payload, password)

            # Convert encrypted bytes to bit string
            binary_message = ''.join(format(b, '08b') for b in encrypted)
            binary_delim = ''.join(format(ord(c), '08b') for c in DELIMITER)
            binary_message += binary_delim

            # Read frames from carrier (WAV expected)
            try:
                with wave.open(carrier, 'rb') as audio:
                    params = audio.getparams()
                    frames = bytearray(list(audio.readframes(audio.getnframes())))
            except Exception as e:
                messagebox.showerror("Error", f"Cannot read audio carrier (use WAV preferably): {e}")
                return

            if len(binary_message) > len(frames):
                messagebox.showerror("Error", f"Audio too small for data. Need {len(binary_message)} bits but carrier has {len(frames)} bytes.")
                return

            # LSB embedding
            for i, bit in enumerate(binary_message):
                frames[i] = (frames[i] & 0xFE) | int(bit)

            # Write output WAV
            try:
                with wave.open(output_path, 'wb') as encoded_audio:
                    encoded_audio.setparams(params)
                    encoded_audio.writeframes(bytes(frames))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save encoded file: {e}")
                return

            # Hide secure folder (attempt)
            try:
                hide_file(secure_folder)
            except Exception as e:
                print(f"Could not hide folder: {e}")

            # After encoding, test play the created encoded audio
            try:
                pygame.mixer.music.load(output_path)
                pygame.mixer.music.play()
                pygame.mixer.music.stop()
                played_ok = True
            except Exception as e:
                played_ok = False
                print(f"Playback test failed: {e}")

            success_msg = f"Data hidden successfully!\nFile: {output_name}\nFolder: {secure_folder}\nPassword: {password}\nPlayable: {'Yes' if played_ok else 'No'}"
            if self.send_email_var.get():
                emailed = self.send_email_with_attachment(output_path, data_type, original_filename, password)
                if emailed:
                    success_msg += f"\nEmail: Sent to {self.receiver_email.get()}"
                else:
                    success_msg += f"\nEmail: Failed"

            messagebox.showinfo("Success", success_msg)
            self.window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data: {e}")

    def test_encoded_audio(self):
        # Look in secure folder for latest _encoded_ file
        folder = self.get_secure_folder()
        try:
            files = [f for f in os.listdir(folder) if f.endswith("_encoded_.wav") or "_encoded_" in f]
        except Exception:
            files = []
        files = [f for f in os.listdir(folder) if "_encoded_" in f]
        if not files:
            messagebox.showwarning("No Files", "No encoded audio files found. Encode first.")
            return
        latest = max(files, key=lambda x: os.path.getctime(os.path.join(folder, x)))
        path = os.path.join(folder, latest)
        try:
            pygame.mixer.music.load(path)
            pygame.mixer.music.play()
            pygame.mixer.music.stop()
            messagebox.showinfo("Test", f"Encoded audio plays OK: {latest}")
        except Exception as e:
            messagebox.showerror("Test Failed", f"Cannot play encoded audio: {e}")


class ExtractTextWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent.root)
        self.window.title("Extract")
        self.window.geometry("660x520")
        self.window.configure(bg='#2b2b2b')

        self.file_path = tk.StringVar()
        self.password = tk.StringVar()
        self.extracted_file_data = None
        self.extracted_filename = None

        try:
            pygame.mixer.init()
        except:
            pass

        self.create_widgets()

    def create_widgets(self):
        main = ttk.Frame(self.window)
        main.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(main, text="Encoded audio file:").grid(row=0, column=0, sticky=tk.W, pady=6)
        ttk.Entry(main, textvariable=self.file_path, width=46).grid(row=0, column=1, padx=6)
        ttk.Button(main, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=6)
        ttk.Button(main, text="▶ Play", command=self.play_audio).grid(row=0, column=3, padx=6)

        ttk.Label(main, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=10)
        ttk.Entry(main, textvariable=self.password, show="*", width=46).grid(row=1, column=1, padx=6)

        ttk.Button(main, text="Extract Data", command=self.extract_data).grid(row=2, column=1, pady=12)
        ttk.Label(main, text="Extracted Content:").grid(row=3, column=0, sticky=tk.W, pady=6)
        self.result_text = scrolledtext.ScrolledText(main, width=80, height=14)
        self.result_text.grid(row=4, column=0, columnspan=4, padx=6, pady=6)

        self.save_button = ttk.Button(main, text="Save Extracted File", command=self.save_extracted_file)
        # initially hidden

    def browse_file(self):
        fn = filedialog.askopenfilename(title="Select encoded audio", filetypes=[("Audio","*.wav *.mp3 *.flac"), ("All","*.*")])
        if fn:
            self.file_path.set(fn)

    def play_audio(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Select file first")
            return
        try:
            pygame.mixer.music.load(self.file_path.get())
            pygame.mixer.music.play()
            pygame.mixer.music.stop()
            messagebox.showinfo("Played", "Audio played OK")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot play audio: {e}")

    def decrypt_data(self, encrypted_data, password):
        try:
            salt = encrypted_data[:16]
            enc = encrypted_data[16:]
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            key = base64.urlsafe_b64encode(key[:32])
            f = Fernet(key)
            return f.decrypt(enc)
        except InvalidToken:
            raise Exception("Invalid password")
        except Exception as e:
            raise Exception(f"Decryption error: {e}")

    def extract_data(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Select encoded audio")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Enter password")
            return

        try:
            with wave.open(self.file_path.get(), 'rb') as audio:
                frames = bytearray(list(audio.readframes(audio.getnframes())))
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read audio: {e}")
            return

        # Extract LSBs
        bits = ''.join(str(b & 1) for b in frames)
        delim_bin = ''.join(format(ord(c), '08b') for c in DELIMITER)
        pos = bits.find(delim_bin)
        if pos == -1:
            messagebox.showwarning("No data", "No hidden data detected")
            return

        encrypted_bin = bits[:pos]
        enc_bytes = bytearray(int(encrypted_bin[i:i+8], 2) for i in range(0, len(encrypted_bin), 8))

        try:
            decrypted = self.decrypt_data(bytes(enc_bytes), self.password.get())
        except Exception as e:
            messagebox.showerror("Decrypt error", str(e))
            return

        # Try to parse
        try:
            # If text header present
            if decrypted.startswith(b"TYPE:TEXT\n"):
                content = decrypted[len(b"TYPE:TEXT\n"):].decode(errors='ignore')
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"--- Extracted Text ---\n\n{content}")
                try:
                    self.save_button.grid_remove()
                except:
                    pass
            elif decrypted.startswith(b"TYPE:FILE\n"):
                # filename line
                parts = decrypted.split(b'\n', 2)
                if len(parts) >= 3:
                    filename_line = parts[1].decode(errors='ignore')
                    filename = filename_line.replace("NAME:", "")
                    filedata = parts[2]
                    self.extracted_filename = filename
                    self.extracted_file_data = filedata
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, f"--- Extracted file ready ---\nFilename: {filename}\nSize: {len(filedata)} bytes\n\nClick Save Extracted File to save it.")
                    # show save button
                    self.save_button.grid(row=5, column=1, pady=6)
                else:
                    raise Exception("Invalid file format")
            else:
                # legacy / raw text
                try:
                    dec_text = decrypted.decode()
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, dec_text)
                except:
                    # binary
                    self.extracted_filename = "extracted.bin"
                    self.extracted_file_data = decrypted
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, f"Binary data extracted ({len(decrypted)} bytes). Use Save Extracted File to save.")
                    self.save_button.grid(row=5, column=1, pady=6)

            messagebox.showinfo("Success", "Extraction completed")
        except Exception as e:
            messagebox.showerror("Error", f"Parsing error: {e}")

    def save_extracted_file(self):
        if not self.extracted_file_data or not self.extracted_filename:
            messagebox.showerror("Error", "No extracted file to save")
            return
        out = filedialog.asksaveasfilename(initialfile=self.extracted_filename, defaultextension=os.path.splitext(self.extracted_filename)[1] or "")
        if out:
            try:
                with open(out, 'wb') as f:
                    f.write(self.extracted_file_data)
                messagebox.showinfo("Saved", f"Saved to {out}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {e}")

class AudioSteganography:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Audio Steganography")
        self.root.geometry("520x520")
        self.root.configure(bg='#2b2b2b')
        self.load_icons()
        self.create_widgets()

    def load_icons(self):
        self.icons = {}
        for key, filename in ICON_FILES.items():
            try:
                if os.path.exists(filename):
                    img = Image.open(filename).resize((40, 40))
                    self.icons[key] = ImageTk.PhotoImage(img)
                else:
                    raise FileNotFoundError
            except Exception:
                # fallback to None (we will use text emoji)
                self.icons[key] = None

    def create_widgets(self):
        main = tk.Frame(self.root, bg='#2b2b2b')
        main.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        tk.Label(main, text="Enhanced Audio Steganography", font=("Arial", 18, "bold"), bg='#2b2b2b', fg='white').pack(pady=8)
        tk.Label(main, text="✨ Hide Text/Files • 🎵 Multi-format • 📧 Email • 🔒 Secure Storage", bg='#2b2b2b', fg='#999').pack(pady=4)

        # icons
        icon_frame = tk.Frame(main, bg='#2b2b2b')
        icon_frame.pack(pady=8)
        if self.icons.get("lock") or self.icons.get("folder") or self.icons.get("music"):
            for k in ("lock", "folder", "music"):
                if self.icons.get(k):
                    lbl = tk.Label(icon_frame, image=self.icons[k], bg='#2b2b2b')
                    lbl.image = self.icons[k]
                    lbl.pack(side=tk.LEFT, padx=12)
                else:
                    tk.Label(icon_frame, text="🔐" if k=="lock" else "📁" if k=="folder" else "🎵", font=("Arial", 28), bg='#2b2b2b', fg='white').pack(side=tk.LEFT, padx=12)
        else:
            tk.Label(icon_frame, text="🔐  📁  🎵", font=("Arial", 40), bg='#2b2b2b', fg='white').pack()

        # buttons
        btn_frame = tk.Frame(main, bg='#2b2b2b')
        btn_frame.pack(pady=18)
        tk.Button(btn_frame, text="🔒 Hide Text/Files", bg='#d32f2f', fg='white', font=("Arial", 12, "bold"), width=20, height=2, command=self.open_hide_window).pack(pady=8)
        tk.Button(btn_frame, text="🔓 Extract Data", bg='#388e3c', fg='white', font=("Arial", 12, "bold"), width=20, height=2, command=self.open_extract_window).pack(pady=8)

        util_frame = tk.Frame(main, bg='#2b2b2b')
        util_frame.pack(pady=6)
        tk.Button(util_frame, text="📁 Manage Secure Folder", bg='#1976d2', fg='white', width=22, command=self.manage_secure_folder).pack(pady=6)
        tk.Button(util_frame, text="ℹ️ Project Info", bg='#424242', fg='white', width=22, command=self.show_project_info).pack(pady=6)

    def open_hide_window(self):
        HideTextWindow(self)

    def open_extract_window(self):
        ExtractTextWindow(self)

    def get_secure_folder(self):
        return HideTextWindow(self).get_secure_folder()

    def manage_secure_folder(self):
        # Look in preferred locations
        possible = [os.path.join(os.path.expanduser("~"), "Documents"),
                    os.path.join(os.path.expanduser("~"), "Desktop"),
                    tempfile.gettempdir()]
        secure = None
        for base in possible:
            folder = os.path.join(base, DEFAULT_SECURE_FOLDER_NAME)
            if os.path.exists(folder):
                secure = folder
                break
        if not secure:
            messagebox.showinfo("No folder", "No secure folder found yet. Encode something first.")
            return
        try:
            files = os.listdir(secure)
            count = len(files)
            size = sum(os.path.getsize(os.path.join(secure, f)) for f in files if os.path.isfile(os.path.join(secure, f)))
            size_mb = round(size / (1024*1024), 2)
            resp = messagebox.askyesnocancel("Secure Folder", f"Folder: {secure}\nFiles: {count}\nSize: {size_mb} MB\n\nYes = Open folder\nNo = Delete all files\nCancel = Do nothing")
            if resp is True:
                if sys.platform == "win32":
                    os.startfile(secure)
                elif sys.platform == "darwin":
                    subprocess.run(["open", secure])
                else:
                    subprocess.run(["xdg-open", secure])
            elif resp is False:
                if messagebox.askyesno("Confirm", "Delete ALL files?"):
                    for f in files:
                        try:
                            os.remove(os.path.join(secure, f))
                        except:
                            pass
                    messagebox.showinfo("Deleted", "All files deleted.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not manage folder: {e}")

    def show_project_info(self):
        info_text = """Enhanced Audio Steganography

Features:
- Hide text or any file inside WAV audio using LSB + AES encryption (Fernet)
- Email encoded audio as attachment
- Play audio to verify encoded file works
- Secure storage folder (auto-hidden)
- Firebase user authentication (create / verify)
Project Name: Audio Steganography with Security Enhancements
Developed By: TEAM 33

Team Members:

* [va2337102@gmail.com](mailto:va2337102@gmail.com)
* [kalidindi.ankitha@gmail.com](mailto:kalidindi.ankitha@gmail.com)
* [saisanjanachowdary@gmail.com](mailto:saisanjanachowdary@gmail.com)
* [23r11a05l0@gcet.edu.in](mailto:23r11a05l0@gcet.edu.in)
* [contact@suprajatechnologies.com](mailto:contact@suprajatechnologies.com)

Supervisor: SANTHOSH CHALUVADI
Company:Supraja Technologies
Year: 2025

Context:
This project focuses on secure communication by embedding hidden messages within audio files using steganography techniques.
It allows users to store, share, and retrieve these audio files securely, with features like email sharing, format compatibility, and password protection.
It is designed to be a robust tool for individuals and organizations requiring discreet and reliable message transmission.

"""
        messagebox.showinfo("Project Info", info_text)

# ----------------------------
# Login & main flow
# ----------------------------
def login_window():
    root = tk.Tk()
    root.title("Login - Audio Steganography")
    root.geometry("360x160")

    tk.Label(root, text="Username:").grid(row=0, column=0, padx=8, pady=8)
    entry_user = tk.Entry(root)
    entry_user.grid(row=0, column=1, padx=8, pady=8)
    tk.Label(root, text="Password:").grid(row=1, column=0, padx=8, pady=8)
    entry_pass = tk.Entry(root, show="*")
    entry_pass.grid(row=1, column=1, padx=8, pady=8)

    def do_login():
        u = entry_user.get().strip()
        p = entry_pass.get().strip()
        if not u or not p:
            messagebox.showerror("Login", "Enter username and password")
            return
        try:
            if verify_user(u, p):
                messagebox.showinfo("Login", "Login successful")
                root.destroy()
                main_app_window()
            else:
                messagebox.showerror("Login", "Invalid credentials")
        except Exception as e:
            messagebox.showerror("Login Error", str(e))

    def do_register():
        u = entry_user.get().strip()
        p = entry_pass.get().strip()
        if not u or not p:
            messagebox.showerror("Register", "Enter username and password")
            return
        try:
            create_user(u, p)
            messagebox.showinfo("Register", "User registered. Now login.")
        except Exception as e:
            messagebox.showerror("Register Error", str(e))

    tk.Button(root, text="Login", command=do_login).grid(row=2, column=0, padx=10, pady=10)
    tk.Button(root, text="Register", command=do_register).grid(row=2, column=1, padx=10, pady=10)
    root.mainloop()

def main_app_window():
    root = tk.Tk()
    app = AudioSteganography(root)
    root.mainloop()

def main():
    # check for required packages basics (best-effort)
    try:
        import pygame, cryptography, PIL
    except Exception:
        print("Make sure required packages are installed: pip install pygame cryptography Pillow pydub firebase-admin")
    login_window()

if __name__ == "__main__":
    main()
