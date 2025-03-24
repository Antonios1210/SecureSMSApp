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

# 32-byte pre-shared key for AES-GCM
SHARED_KEY = b'ThisIsASecretKeyForAES256Encrypt'

# Keep track of connected clients
clients = []

def validate_token(token):
    """
    1) Fetch signing keys from the Azure AD v2.0 JWKS URL.
    2) Decode the token with 'verify_signature' only,
       skipping issuer/audience checks in the built-in decode.
    3) Manually check issuer is one of the 2 valid patterns:
       https://sts.windows.net/<TENANT_ID>/  OR
       https://login.microsoftonline.com/<TENANT_ID>/v2.0
    4) Manually check the audience matches api://<CLIENT_ID>.
    """
    try:
        # Quick format check
        if not token or len(token.split(".")) != 3:
            return False, "Invalid JWT format"

        # Use v2.0 keys (recommended for modern tokens)
        # This is crucial if your tokens come from the v2.0 endpoint
        jwks_url = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)

        # Decode with signature verification only
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={
                "verify_iss": False,  # We'll do it manually
                "verify_aud": False,  # We'll do it manually
            },
        )

        # Manually enforce the known issuers
        allowed_issuers = [
            f"https://sts.windows.net/{TENANT_ID}/",
            f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        ]
        actual_iss = decoded.get("iss", "")
        if actual_iss not in allowed_issuers:
            return False, f"Issuer mismatch (got '{actual_iss}')"

        # Manually enforce audience
        actual_aud = decoded.get("aud", "")
        expected_aud = f"api://{CLIENT_ID}"
        if actual_aud != expected_aud:
            return False, f"Audience mismatch (got '{actual_aud}')"

        return True, "Valid"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)}"


def recvall(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def broadcast_message(sender_socket, nickname, plaintext):
    full_text = f"[{nickname}] {plaintext.decode(errors='replace')}"
    for cli_sock, cli_nick in clients:
        try:
            aesgcm = AESGCM(SHARED_KEY)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, full_text.encode(), None)

            packet = (
                b"MSG"
                + len(nonce).to_bytes(2, 'big')
                + nonce
                + len(ciphertext).to_bytes(4, 'big')
                + ciphertext
            )
            cli_sock.sendall(packet)
        except Exception as e:
            print(f"Failed to broadcast to {cli_nick}: {e}")

def handle_client(client_sock):
    nickname = None
    try:
        client_sock.settimeout(60)

        # Wait for "nickname|token"
        data = b''
        while b'|' not in data:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            data += chunk

        if b'|' not in data:
            client_sock.sendall(b"ERR|No '|' in the initial handshake")
            return

        nickname, token = data.decode().split('|', 1)
        token = token.strip()

        # Validate
        is_valid, msg = validate_token(token)
        if not is_valid:
            print(f"[SERVER] Token validation failed for {nickname}, reason: {msg}")
            client_sock.sendall(f"ERR|{msg}".encode())
            return

        # Auth success
        client_sock.sendall(b'AUTH_OK')
        print(f"[SERVER] {nickname} authenticated successfully.")
        clients.append((client_sock, nickname))

        aesgcm = AESGCM(SHARED_KEY)
        print("[SERVER] AES-GCM initialized with shared key for client:", nickname)

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
                broadcast_message(client_sock, nickname, plaintext)
            except Exception as e:
                print(f"Decryption error for {nickname}: {e}")
    except Exception as e:
        print(f"Error in handle_client for {nickname}: {e}")
    finally:
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
