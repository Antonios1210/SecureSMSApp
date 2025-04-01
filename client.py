import socket
import msal
import os
import sys
import time
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import webbrowser
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SERVER_HOST = "10.0.1.4"
SERVER_PORT = 4000

TENANT_ID = "2940786f-5af0-48fb-adb7-56da78440d61"
CLIENT_ID = "2cfbeb4e-3216-485c-bbc3-8f408b55a969"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = [f"api://{CLIENT_ID}/access_as_user"]

###############################################################################
# Behavioral Key-Derivation Function (AES & HMAC)
###############################################################################
def derive_keys(user_id: str, time_slice: str) -> (bytes, bytes):
    """
    Derives two keys (one for AES-GCM encryption, one for HMAC) from a master secret
    based on the user's identifier + a time slice (e.g. the current minute).
    """
    seed = f"{user_id}|{time_slice}"
    # 1) Take a SHA-256 of the seed
    master = hashlib.sha256(seed.encode()).digest()
    # 2) HKDF to expand into 64 bytes, then split into two keys
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'secure_sms_behavioral')
    key_material = hkdf.derive(master)
    aes_key = key_material[:32]
    hmac_key = key_material[32:]
    return aes_key, hmac_key

###############################################################################
# A helper function to receive an exact number of bytes (like recvall).
###############################################################################
def recvall(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

###############################################################################
# The main UI-based secure chat client class
###############################################################################
class SecureChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")

        self.sock = None
        self.aesgcm = None
        self.hmac_key = None
        self.time_slice = None

        # -------------------- UI Elements --------------------
        self.chat_display = scrolledtext.ScrolledText(master, wrap=tk.WORD, state='disabled', width=60, height=20)
        self.chat_display.pack(padx=10, pady=10)

        self.msg_entry = tk.Entry(master, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10))
        self.msg_entry.bind('<Return>', lambda e: self.send_message())

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=10, pady=(0, 10))

        self.status_label = tk.Label(master, text="Disconnected", fg="red")
        self.status_label.pack(side=tk.BOTTOM, pady=(0, 5))

        # Prompt user for nickname
        self.nickname = simpledialog.askstring("Nickname", "Enter your nickname:")
        if not self.nickname:
            master.destroy()
            return

        # Attempt to connect
        self.connect()

    def append_chat(self, msg):
        """Utility to safely add text into the chat display."""
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, msg + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    ###############################################################################
    # Device flow: get_token() with MSAL, but using a popup for the user
    ###############################################################################
    def get_token(self):
        try:
            # Create MSAL PublicClientApplication
            app = msal.PublicClientApplication(client_id=CLIENT_ID, authority=AUTHORITY)
            # Initiate the device flow
            flow = app.initiate_device_flow(scopes=SCOPE)
            if "user_code" not in flow:
                raise Exception("Device flow failed")

            # Pop up to let the user follow the link and code
            self.show_device_login_popup(flow['verification_uri'], flow['user_code'])
            # Wait for user to close the popup (i.e., they've finished logging in)
            self.master.wait_window(self.login_popup)

            token_response = app.acquire_token_by_device_flow(flow)
            return token_response["access_token"]
        except Exception as e:
            messagebox.showerror("Authentication Error", str(e))
            self.master.destroy()
            sys.exit(1)

    def show_device_login_popup(self, uri, code):
        """A small popup with a clickable login URL and code."""
        self.login_popup = tk.Toplevel(self.master)
        self.login_popup.title("Device Login")
        self.login_popup.geometry("400x160")

        link_label = tk.Label(self.login_popup, text=uri, fg="blue", cursor="hand2")
        link_label.pack(pady=(20, 5))
        link_label.bind("<Button-1>", lambda e: webbrowser.open_new(uri))

        code_label = tk.Label(self.login_popup, text=f"Code: {code}", font=("Courier", 12))
        code_label.pack(pady=(5, 5))

        # Copy code to clipboard
        self.master.clipboard_clear()
        self.master.clipboard_append(code)
        messagebox.showinfo("Copied", "Code copied to clipboard!")

        ok_button = tk.Button(self.login_popup, text="I've Logged In", command=self.login_popup.destroy)
        ok_button.pack(pady=(10, 10))

    ###############################################################################
    # Establish the socket connection, do handshake, derive keys, spawn recv thread
    ###############################################################################
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            # A more generous timeout for user interaction
            self.sock.settimeout(300)

            # Acquire token
            token = self.get_token().strip()

            # Derive a time_slice (the current minute)
            self.time_slice = str(int(time.time()) // 60)

            # Send handshake: nickname|token|time_slice
            self.sock.sendall(f"{self.nickname}|{token}|{self.time_slice}".encode())

            # Check authentication from server
            auth_response = recvall(self.sock, 7)
            if auth_response != b"AUTH_OK":
                messagebox.showerror("Authentication Failed", auth_response.decode(errors='replace'))
                self.master.destroy()
                return

            # Mark connected
            self.status_label.config(text="Connected", fg="green")
            self.append_chat("[Info] Authentication successful. Connected to server.")

            # Derive AES and HMAC keys
            aes_key, self.hmac_key = derive_keys(self.nickname, self.time_slice)
            self.aesgcm = AESGCM(aes_key)

            # Start a thread to continuously read from server
            threading.Thread(target=self.receive_thread, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.master.destroy()

    ###############################################################################
    # Receiving messages in a background thread
    ###############################################################################
    def receive_thread(self):
        try:
            while True:
                # Expect a 'MSG' header
                header = recvall(self.sock, 3)
                if not header or header != b"MSG":
                    break

                # Nonce length
                nonce_length_bytes = recvall(self.sock, 2)
                if len(nonce_length_bytes) < 2:
                    break
                nonce_length = int.from_bytes(nonce_length_bytes, 'big')
                nonce = recvall(self.sock, nonce_length)

                # Ciphertext length
                ct_length_bytes = recvall(self.sock, 4)
                if len(ct_length_bytes) < 4:
                    break
                ct_length = int.from_bytes(ct_length_bytes, 'big')
                ciphertext = recvall(self.sock, ct_length)

                # Decrypt
                plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
                # The plaintext includes the message and the HMAC, separated by ||HMAC||
                if b'||HMAC||' not in plaintext:
                    raise ValueError("Missing HMAC delimiter in incoming message.")

                message_part, received_hmac = plaintext.rsplit(b'||HMAC||', 1)
                # Recompute HMAC to verify
                expected_hmac = hmac.new(self.hmac_key, message_part, hashlib.sha256).digest()
                if not hmac.compare_digest(received_hmac, expected_hmac):
                    raise ValueError("HMAC verification failed for incoming message.")

                # Everything checks out
                self.append_chat(message_part.decode(errors='replace'))

        except Exception as e:
            self.append_chat(f"[Error receiving]: {str(e)}")

    ###############################################################################
    # Sending messages
    ###############################################################################
    def send_message(self):
        msg = self.msg_entry.get().strip()
        if not msg or not self.aesgcm:
            return
        self.msg_entry.delete(0, tk.END)

        try:
            # Combine message + HMAC
            # 1) Generate HMAC of the plaintext
            hmac_digest = hmac.new(self.hmac_key, msg.encode(), hashlib.sha256).digest()
            msg_with_hmac = msg.encode() + b'||HMAC||' + hmac_digest

            # 2) Encrypt using AES-GCM
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, msg_with_hmac, None)

            # 3) Construct packet
            packet = (
                b"MSG"
                + len(nonce).to_bytes(2, 'big')
                + nonce
                + len(ciphertext).to_bytes(4, 'big')
                + ciphertext
            )

            # 4) Send
            self.sock.sendall(packet)

            # Echo to local chat
            self.append_chat(f"[You]: {msg}")

        except Exception as e:
            self.append_chat(f"[Send Error]: {str(e)}")

###############################################################################
# Main: Launch the tkinter-based UI
###############################################################################
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()
