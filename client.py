import socket
import msal
import os
import sys
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = "10.0.1.4"
SERVER_PORT = 4000

TENANT_ID = "2940786f-5af0-48fb-adb7-56da78440d61"
CLIENT_ID = "2cfbeb4e-3216-485c-bbc3-8f408b55a969"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = [f"api://{CLIENT_ID}/access_as_user"]

SHARED_KEY = b'ThisIsASecretKeyForAES256Encrypt'

def get_token():
    try:
        app = msal.PublicClientApplication(client_id=CLIENT_ID, authority=AUTHORITY)
        flow = app.initiate_device_flow(scopes=SCOPE)
        if "user_code" not in flow:
            print("Device flow failed")
            sys.exit(1)
        print(f"\nOpen {flow['verification_uri']} and enter code: {flow['user_code']}")
        token_response = app.acquire_token_by_device_flow(flow)
        return token_response["access_token"]
    except Exception as e:
        print(f"Token error: {str(e)}")
        sys.exit(1)

def recvall(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        sock.settimeout(60)

        nickname = input("Nickname: ").strip()
        token = get_token().strip()

        # Send "nickname|token"
        sock.sendall(f"{nickname}|{token}".encode())

        # Wait for server's auth confirmation (7 bytes)
        auth_response = recvall(sock, 7)
        if auth_response != b'AUTH_OK':
            print("Authentication failed:", auth_response.decode(errors='replace'))
            return

        print("Authentication successful. Connected!")
        aesgcm = AESGCM(SHARED_KEY)
        print(f"AES-GCM initialized with shared key for client: {nickname}")

        def receive_thread():
            while True:
                try:
                    header = recvall(sock, 3)
                    if not header or header != b"MSG":
                        break
                    nonce_length_bytes = recvall(sock, 2)
                    if len(nonce_length_bytes) < 2:
                        break
                    nonce_length = int.from_bytes(nonce_length_bytes, 'big')
                    nonce = recvall(sock, nonce_length)

                    ct_length_bytes = recvall(sock, 4)
                    if len(ct_length_bytes) < 4:
                        break
                    ct_length = int.from_bytes(ct_length_bytes, 'big')
                    ciphertext = recvall(sock, ct_length)

                    msg = aesgcm.decrypt(nonce, ciphertext, None)
                    msg_str = msg.decode(errors='replace')
                    print(msg_str)

                except Exception as e:
                    print("Error in receiving messages:", str(e))
                    break

        threading.Thread(target=receive_thread, daemon=True).start()

        # Sending loop
        while True:
            msg = input("")
            if not msg:
                continue
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, msg.encode(), None)
            packet = (
                b"MSG"
                + len(nonce).to_bytes(2, 'big')
                + nonce
                + len(ciphertext).to_bytes(4, 'big')
                + ciphertext
            )
            sock.sendall(packet)

    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
