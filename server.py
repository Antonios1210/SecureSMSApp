import socket
import threading
import jwt
import os
import time
import hmac
import hashlib
from jwt import PyJWKClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 4000

# Azure AD IDs to validate whether JWTs (JSON Web Tokens) came from a trusted Microsoft account
TENANT_ID = "2940786f-5af0-48fb-adb7-56da78440d61"
CLIENT_ID = "2cfbeb4e-3216-485c-bbc3-8f408b55a969"

# Previously hardcoded keys are now replaced with derived keys.
# The following static definitions have been removed:
# SHARED_KEY = b'ThisIsASecretKeyForAES256Encrypt'
# HMAC_KEY = b"ThisIsASecretKeyForHMAC256"

# Store connected clients as a tuple consisting of their associated socket, nickname, AESGCM instance, and HMAC key
clients = []

# Function to fetch the public key from Microsoft's JWKS endpoint to validate the JWT
def fetch_signing_key(token, jwks_url):
    jwk_client = PyJWKClient(jwks_url)
    return jwk_client.get_signing_key_from_jwt(token)

# Function to decode the JWT using the public key to verify it is authentic and signed by Microsoft
def try_decode_jwt(token, signing_key):
    decoded = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        options={"verify_iss": False, "verify_aud": False},
    )
    return decoded

# Function to validate:
# 1) The JWT format is correct, 
# 2) It is signed by Microsoft (via JWKS keys)
# 3) The issuer and audience match the expected values 
def validate_token(token):
    try:
        # Check if the JWT format is correct
        if not token or len(token.split(".")) != 3:
            return False, "Invalid JWT format (not 3 segments)"

        # Define the allowed issuers of the JWK
        allowed_issuers = [
            f"https://sts.windows.net/{TENANT_ID}/",
            f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        ]

        # 1) Try v2.0 JWT keys first
        v2_jwks = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
        try:
            signing_key = fetch_signing_key(token, v2_jwks)
            decoded = try_decode_jwt(token, signing_key)
        # 2) Fallback to v1.0 JWT keys if v2.0 fails
        except Exception:
            v1_jwks = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys"
            signing_key = fetch_signing_key(token, v1_jwks)
            decoded = try_decode_jwt(token, signing_key)

        # Check if the JWT issuer is correct. If not, return false
        actual_iss = decoded.get("iss", "")
        if actual_iss not in allowed_issuers:
            return False, f"Issuer mismatch (got '{actual_iss}')"

        # Check if the audience is correct. If not, return false
        actual_aud = decoded.get("aud", "")
        expected_aud = f"api://{CLIENT_ID}"
        if actual_aud != expected_aud:
            return False, f"Audience mismatch (got '{actual_aud}')"

        # If JWK format is correct, signed by Microsoft, issuer is correct, and audience is correct return true
        return True, "Valid"
    
    # If JWK format is not correct, not signed by Microsoft, issuer is not correct, 
    # or audience is not correct, throw an exception and return false
    except Exception as e:
        return False, str(e)

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
    Derives two keys (one for AES and one for HMAC) from a master secret based on the user's identifier and a time slice.
    The master secret is created by concatenating the user_id and the time_slice.
    HKDF is then used to derive 64 bytes of key material, split into a 32-byte AES key and a 32-byte HMAC key.
    """
    seed = f"{user_id}|{time_slice}"
    master = hashlib.sha256(seed.encode()).digest()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'secure_sms_behavioral')
    key_material = hkdf.derive(master)
    aes_key = key_material[:32]
    hmac_key = key_material[32:]
    return aes_key, hmac_key

# Function to encrypt and send the message to all other connected clients
def broadcast_message(sender_socket, nickname, plaintext):
    full_text = f"[{nickname}] {plaintext.decode(errors='replace')}"
    # For each client, re-encrypt the broadcast message using that client's derived AES key
    for (cli_sock, cli_nick, aesgcm, hmac_key) in clients:
        try:
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
            print(f"Failed to broadcast to {cli_nick}: {str(e)}")

# Function to handle a client
def handle_client(client_sock):
    # Initialize a nickname
    nickname = None
    
    try:
        # Timeout after 60 seconds if the client does not respond 
        client_sock.settimeout(60)

        # Wait for the client to send their nickname, JWT, and time_slice (handshake)
        data = b''
        # Expecting two '|' delimiters in the handshake (nickname|token|time_slice)
        while data.count(b'|') < 2:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            data += chunk

        if data.count(b'|') < 2:
            client_sock.sendall(b"ERR|Incomplete handshake")
            return

        # Separate the nickname, token, and time_slice
        parts = data.decode().split('|')
        if len(parts) < 3:
            client_sock.sendall(b"ERR|Incomplete handshake")
            return
        nickname = parts[0]
        token = parts[1].strip()
        time_slice = parts[2].strip()

        # Verify if the JWT is authentic using JWT keys
        is_valid, msg = validate_token(token)
        if not is_valid:
            client_sock.sendall(f"ERR|{msg}".encode())
            return

        # Derive keys using the behavioral entropy-based function
        aes_key, hmac_key = derive_keys(nickname, time_slice)
        aesgcm = AESGCM(aes_key)

        # Add the client to the clients list of authenticated connected clients 
        # (a tuple consisting of their associated socket, nickname, AESGCM instance, and HMAC key)
        client_sock.sendall(b'AUTH_OK')
        print(f"[SERVER] {nickname} authenticated successfully.")
        clients.append((client_sock, nickname, aesgcm, hmac_key))

        # Print to the server terminal that the client is initialized with the derived key
        print("[SERVER] AES-GCM initialized with derived key for client:", nickname)

        # Set an infinite loop to keep accepting messages from a connected client
        while True:
            # Check to make sure the header of the incoming message is a proper message starting with MSG
            # If not, stop handling the client
            header = recvall(client_sock, 3)
            if not header or header != b"MSG":
                break

            # Get the nonce length in bytes
            nonce_length_bytes = recvall(client_sock, 2)
            if len(nonce_length_bytes) < 2:
                break

            # Convert the nonce length from bytes to a number
            nonce_length = int.from_bytes(nonce_length_bytes, 'big')
            
            # Get the value of the nonce to be used for AES-GCM decryption
            nonce = recvall(client_sock, nonce_length)

            # Get the ciphertext length in bytes
            ct_length_bytes = recvall(client_sock, 4)
            if len(ct_length_bytes) < 4:
                break

            # Convert the ciphertext length from bytes to a number
            ct_length = int.from_bytes(ct_length_bytes, 'big')
            
            # Get the value of the ciphertext
            ciphertext = recvall(client_sock, ct_length)

            try:
                # Decrypt the message using AES-GCM
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)

                # HMAC Verification
                # Check if the message is missing the delimiter that separates it from the HMAC
                # If it is missing, raise an exception that it is missing
                if b'||HMAC||' not in plaintext:
                    raise ValueError("Missing HMAC delimiter")

                # Separate the message from the HMAC
                message_part, received_hmac = plaintext.rsplit(b'||HMAC||', 1)
                
                # Generate the HMAC using the derived HMAC key and the received message
                expected_hmac = hmac.new(hmac_key, message_part, hashlib.sha256).digest()

                # Check if the expected HMAC matches the received HMAC to verify integrity
                # If it does not match, raise an exception that the verification failed
                if not hmac.compare_digest(received_hmac, expected_hmac):
                    raise ValueError("HMAC verification failed")

                # If decryption, missing delimiter, and invalid HMAC checks ALL pass
                # Then, log the message and client nickname and broadcast the message to all connected clients
                print(f"{nickname}: {message_part.decode(errors='replace')}")
                broadcast_message(client_sock, nickname, message_part)

            # If any of the decryption, missing delimiter, or invalid HMAC checks fail,
            # raise an exception that the message failed to pass the integrity check
            except Exception as e:
                print(f"[SECURITY] Message from {nickname} failed integrity check: {str(e)}")

    # If any of the checks fail, raise an exception and print there was an error
    # The message will not be broadcasted to the other connected clients
    except Exception as e:
        print(f"Error in handle_client for {nickname}: {str(e)}")
    
    # Once a connected client disconnects, remove them from the clients list
    finally:
        print(f"[SERVER] {nickname} disconnected.")
        for i, (s, n, _, _) in enumerate(clients):
            if s == client_sock:
                clients.pop(i)
                break

        # Close the socket
        client_sock.close()

# Main function to set up the server and accept incoming client connections and create threads
def main():
    # Set up the server, bind it, and wait for an incoming client connection
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    
    # Print to the server terminal that the server is running
    print(f"Server running on {SERVER_HOST}:{SERVER_PORT}")
    
    while True:
        # Accept an incoming client connection
        client, addr = server.accept()
        
        # Print to the server terminal that the client is connected
        print(f"New connection from {addr}")

        # Create a thread for the client
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        
# Start the program
if __name__ == "__main__":
    main()
