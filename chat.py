from flask import Flask
from flask_socketio import SocketIO
import base64
from Crypto.Cipher import AES
from Crypto.Hash import MD5

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
PASSPHRASE = "this-is-a-shared-secret-key"

def derive_key_and_iv(password, salt, key_len=32, iv_len=16):
    d = d_i = b""
    while len(d) < key_len + iv_len:
        d_i = MD5.new(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len+iv_len]

def decrypt_cryptojs(encrypted_b64, passphrase):
    encrypted = base64.b64decode(encrypted_b64)
    assert encrypted[:8] == b"Salted__", "Invalid data (missing Salted__ prefix)"
    salt = encrypted[8:16]
    ciphertext = encrypted[16:]
    key, iv = derive_key_and_iv(passphrase.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    padding_len = decrypted[-1]
    return decrypted[:-padding_len].decode("utf-8")

@socketio.on("chat")
def handle_chat(encrypted_msg):
    print("\nEncrypted:", encrypted_msg)
    try:
        decrypted_msg = decrypt_cryptojs(encrypted_msg, PASSPHRASE)
    except Exception as e:
        decrypted_msg = f"[DECRYPTION FAILED: {e}]"
    print("Decrypted:", decrypted_msg)
    socketio.emit("chat", encrypted_msg)

if __name__ == "__main__":
    socketio.run(app, debug=True)
