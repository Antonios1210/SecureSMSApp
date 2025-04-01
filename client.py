import socket
import msal
import os
import sys
import threading
import time
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SERVER_HOST = "10.0.1.4"
SERVER_PORT = 4000

# Azure AD IDs to validate whether JWTs (JSON Web Tokens) came from a trusted Microsoft account
TENANT_ID = "2940786f-5af0-48fb-adb7-56da78440d61"
CLIENT_ID = "2cfbeb4e-3216-485c-bbc3-8f408b55a969"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = [f"api://{CLIENT_ID}/access_as_user"]


# Function to handle Microsoft’s device login flow 
def get_token():
    try:
        # Create a client app that will request a token
        app = msal.PublicClientApplication(client_id=CLIENT_ID, authority=AUTHORITY)
        
        # Begin device login flow
        flow = app.initiate_device_flow(scopes=SCOPE)
        
        # Check if the response provided a login code
        if "user_code" not in flow:
            print("Device flow failed")
            sys.exit(1)

        # Prompt the client to go to the URL and enter the login code
        print(f"\nOpen {flow['verification_uri']} and enter code: {flow['user_code']}")
        
        # Wait for the login process to complete and return the access token
        token_response = app.acquire_token_by_device_flow(flow)
        return token_response["access_token"]
    
    # If any of the checks failed, throw an exception and print that there was a token error
    except Exception as e:
        print(f"Token error: {str(e)}")
        sys.exit(1)

# Function to keep receiving chunks of data until the full message is received
def recvall(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def derive_keys(user_id: str, time_slice: str) -> (bytes, bytes):
    """
    Derives two independent keys from a master secret based on behavioral entropy.
    The master secret is built from the user identifier and the current time slice (in minutes).
    HKDF is then used to produce 64 bytes of key material, which are split into:
      - a 32-byte AES-GCM key
      - a 32-byte HMAC key
    """
    seed = f"{user_id}|{time_slice}"
    master = hashlib.sha256(seed.encode()).digest()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'secure_sms_behavioral')
    key_material = hkdf.derive(master)
    aes_key = key_material[:32]
    hmac_key = key_material[32:]
    return aes_key, hmac_key

def main():
    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        sock.connect((SERVER_HOST, SERVER_PORT))

        # Timeout after 300 seconds
        sock.settimeout(300)

        # Prompt the client for their nickname
        nickname = input("Nickname: ").strip()
        
        # Get the token
        token = get_token().strip()

        # Get the current time slice (e.g., current minute) as a string
        time_slice = str(int(time.time()) // 60)

        # Send the nickname, token, and time_slice to the server (handshake)
        sock.sendall(f"{nickname}|{token}|{time_slice}".encode())

        # Wait for server's authentication confirmation
        auth_response = recvall(sock, 7)

        # If the authentication failed, print to the client terminal that it failed
        if auth_response != b'AUTH_OK':
            print("Authentication failed:", auth_response.decode(errors='replace'))
            return

        # Print to the client terminal that the authentication and connection was successful
        print("Authentication successful. Connected!")
        
        # Derive AES and HMAC keys using the behavioral entropy-based function
        aes_key, hmac_key = derive_keys(nickname, time_slice)

        # Initialize AES-GCM with the derived AES key
        aesgcm = AESGCM(aes_key)
        print(f"AES-GCM initialized with derived key for client: {nickname}")

        # Nested function to receive other client messages
        def receive_thread():
            while True:
                try:
                    # Wait for a message with a valid MSG header from the server
                    header = recvall(sock, 3)
                    if not header or header != b"MSG":
                        break
                    
                    # Get the nonce length in bytes
                    nonce_length_bytes = recvall(sock, 2)
                    if len(nonce_length_bytes) < 2:
                        break

                    # Convert the nonce length from bytes to a number
                    nonce_length = int.from_bytes(nonce_length_bytes, 'big')
                    
                    # Get the value of the nonce to be used for AES-GCM decryption
                    nonce = recvall(sock, nonce_length)

                    # Get the ciphertext length in bytes
                    ct_length_bytes = recvall(sock, 4)
                    if len(ct_length_bytes) < 4:
                        break

                    # Convert the ciphertext length from bytes to a number
                    ct_length = int.from_bytes(ct_length_bytes, 'big')
                    
                    # Get the value of the ciphertext
                    ciphertext = recvall(sock, ct_length)

                    # Decrypt the message using AES-GCM
                    msg = aesgcm.decrypt(nonce, ciphertext, None)
                    msg_str = msg.decode(errors='replace')
                    
                    # Print the message
                    print(msg_str)

                # If any of the checks fail, throw an exception and print that there was an error 
                # in receiving the message
                except Exception as e:
                    print("Error in receiving messages:", str(e))
                    break

        # Enable messages to be received and sent at the same time
        threading.Thread(target=receive_thread, daemon=True).start()

        # Infinite loop to send messages
        while True:
            # Receive the client's input 
            msg = input("")
            if not msg:
                continue

            # Generate an HMAC over the plaintext message using the derived HMAC key
            hmac_digest = hmac.new(hmac_key, msg.encode(), hashlib.sha256).digest()

            # Combine the HMAC with the message separated by a delimiter
            msg_with_hmac = msg.encode() + b'||HMAC||' + hmac_digest 

            # Generate a random 12 byte nonce for encryption
            nonce = os.urandom(12)
            
            # Encrypt the plaintext message and HMAC with the nonce 
            ciphertext = aesgcm.encrypt(nonce, msg_with_hmac, None)
            
            # Build the packet to be sent
            packet = (
                b"MSG"
                + len(nonce).to_bytes(2, 'big')
                + nonce
                + len(ciphertext).to_bytes(4, 'big')
                + ciphertext
            )

            # Send the encrypted packet to the server
            sock.sendall(packet)

    except KeyboardInterrupt:
        print("\nExiting...")
    
    # Close the socket
    finally:
        sock.close()

# Start the program
if __name__ == "__main__":
    main()
