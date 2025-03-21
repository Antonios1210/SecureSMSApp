import socket
import threading
import jwt
import os
from jwt import PyJWKClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 4000

TENANT_ID = "2940786f-5af0-48fb-adb7-56da78440d61"
CLIENT_ID = "2cfbeb4e-3216-485c-bbc3-8f408b55a969"

# Pre-shared 256-bit key (32 bytes)
SHARED_KEY = b'ThisIsASecretKeyForAES256Encrypt'

# A global list of (socket, nickname) for all connected clients
clients = []

def validate_token(token):
    try:
        if not token or len(token.split('.')) != 3:
            return False, "Invalid JWT format"
        jwks_url = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys"
        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=f"api://{CLIENT_ID}",
            issuer=f"https://sts.windows.net/{TENANT_ID}/"
        )
        return True, "Valid"
    except Exception as e:
        return False, str(e)

def recvall(sock, length):
    """Receive exactly length bytes from a socket."""
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def broadcast_message(sender_socket, nickname, plaintext):
    """
    Re-encrypts the plaintext and broadcasts it to all connected clients,
    including the sender. This ensures everyone sees "[nickname] message".
    """
    full_text = f"[{nickname}] {plaintext.decode(errors='replace')}"
    message_bytes = full_text.encode()

    # Broadcast to every client in the list
    for (cli_sock, cli_nick) in clients:
        try:
            aesgcm = AESGCM(SHARED_KEY)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, message_bytes, None)

            # Construct the same wire format: "MSG" + <nonce-len> + nonce + <ct-len> + ciphertext
            packet = (
                b"MSG"
                + len(nonce).to_bytes(2, 'big')
                + nonce
                + len(ciphertext).to_bytes(4, 'big')
                + ciphertext
            )
            cli_sock.sendall(packet)
        except Exception as e:
            print(f"Failed to broadcast to {cli_nick}: {str(e)}")

def handle_client(client_sock):
    nickname = None
    try:
        client_sock.settimeout(60)
        # Receive authentication data: nickname|token
        data = b''
        while b'|' not in data:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            data += chunk

        if b'|' not in data:
            client_sock.sendall(b"ERR|Invalid format")
            return

        nickname, token = data.decode().split('|', 1)
        valid, msg = validate_token(token.strip())
        if not valid:
            client_sock.sendall(f"ERR|{msg}".encode())
            return

        # Authentication successful; send confirmation
        client_sock.sendall(b'AUTH_OK')
        print(f"[SERVER] {nickname} authenticated successfully.")

        # Store this client in the global list
        clients.append((client_sock, nickname))

        # Initialize AES-GCM with the pre-shared key for receiving from THIS client
        aesgcm = AESGCM(SHARED_KEY)
        print("[SERVER] AES-GCM initialized with shared key for client:", nickname)

        # Process incoming encrypted messages
        while True:
            header = recvall(client_sock, 3)
            if not header or header != b"MSG":
                break

            nonce_length_bytes = recvall(client_sock, 2)
            if len(nonce_length_bytes) < 2:
                break
            nonce_length = int.from_bytes(nonce_length_bytes, 'big')

            nonce = recvall(client_sock, nonce_length)
            ct_length_bytes = recvall(client_sock, 4)
            if len(ct_length_bytes) < 4:
                break
            ct_length = int.from_bytes(ct_length_bytes, 'big')
            ciphertext = recvall(client_sock, ct_length)

            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                print(f"{nickname}: {plaintext.decode(errors='replace')}")
                # Now broadcast to all clients (including the sender)
                broadcast_message(client_sock, nickname, plaintext)

            except Exception as e:
                print(f"Decryption error for {nickname}: {str(e)}")

    except Exception as e:
        print(f"Error in handle_client for {nickname}: {str(e)}")

    finally:
        # Remove from global list
        print(f"[SERVER] {nickname} disconnected.")
        for i, (s, n) in enumerate(clients):
            if s == client_sock:
                clients.pop(i)
                break
        client_sock.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"Server running on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client, addr = server.accept()
        print(f"New connection from {addr}")
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    main()
