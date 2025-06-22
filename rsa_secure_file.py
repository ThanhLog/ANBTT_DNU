from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import hashlib
import base64

# Băm mật khẩu bằng SHA-256
def hash_password_sha(password):
    sha = hashlib.sha256()
    sha.update(password.encode())
    return sha.digest()

# Sinh khóa hợp lệ cho Triple DES (24 bytes)
def generate_3des_key():
    while True:
        key = get_random_bytes(24)
        try:
            DES3.adjust_key_parity(key)
            return key
        except ValueError:
            continue

# Mã hóa mật khẩu đã băm bằng 3DES
def encrypt_hashed_password(hashed_password, key):
    cipher = DES3.new(key, DES3.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(hashed_password)
    return base64.b64encode(nonce + ciphertext).decode()

# Xác minh mật khẩu khi đăng nhập
def verify_password(input_password, encrypted_hash_b64, key):
    raw = base64.b64decode(encrypted_hash_b64)
    nonce = raw[:16]
    ciphertext = raw[16:]
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
    hashed_input = hash_password_sha(input_password)
    try:
        decrypted_hash = cipher.decrypt(ciphertext)
        return hashed_input == decrypted_hash
    except:
        return False

if __name__ == "__main__":
    # Sinh khóa 3DES
    key = generate_3des_key()

    # # Người dùng đăng ký
    # password = "MySecret123"
    # hashed = hash_password_sha(password)
    # encrypted = encrypt_hashed_password(hashed, key)
    # print("🔐 Mật khẩu đã mã hóa:", encrypted)

    # # Người dùng đăng nhập
    # input_pw = "MySecret123"
    # result = verify_password(input_pw, encrypted, key)
    # print("✅ Xác thực người dùng:", "Thành công" if result else "Thất bại")
    