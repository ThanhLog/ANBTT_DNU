
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Tạo cặp khóa RSA
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Lưu khóa vào file
def save_keys(private_key, public_key):
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Mã hóa file bằng khóa công khai
def encrypt_file(input_file, output_file, public_key):
    with open(input_file, "rb") as f:
        data = f.read()

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    with open(output_file, "wb") as f:
        f.write(encrypted)

# Giải mã file bằng khóa riêng
def decrypt_file(encrypted_file, output_file, private_key):
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()

    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    with open(output_file, "wb") as f:
        f.write(decrypted)

# Tạo chữ ký số từ file
def sign_file(file_path, private_key):
    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

# Xác minh chữ ký số
def verify_signature(file_path, signature, public_key):
    with open(file_path, "rb") as f:
        data = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Ví dụ sử dụng
if __name__ == "__main__":
    # 1. Tạo khóa
    private_key, public_key = generate_keys()
    save_keys(private_key, public_key)

    # 2. Mã hóa file
    encrypt_file("message.txt", "message_encrypted.bin", public_key)

    # 3. Giải mã file
    decrypt_file("message_encrypted.bin", "message_decrypted.txt", private_key)

    # 4. Ký và xác minh
    signature = sign_file("message.txt", private_key)
    result = verify_signature("message.txt", signature, public_key)

    print("✅ Xác thực người dùng:", "Thành công" if result else "Thất bại")