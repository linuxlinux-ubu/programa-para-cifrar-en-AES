from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Función para cifrar un mensaje utilizando AES
def encrypt_message(message, key):
    # Generar un vector de inicialización aleatorio
    iv = os.urandom(16)

    # Crear un cifrador AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Agregar padding al mensaje
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    # Cifrar el mensaje
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Devolver IV y el texto cifrado
    return iv + ciphertext

# Función para descifrar un mensaje cifrado utilizando AES
def decrypt_message(ciphertext, key, iv):
    # Crear un descifrador AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descifrar el mensaje
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Quitar el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return original_data

# Ejemplo de uso
def main():
    # Mensaje a cifrar
    message = b"tu-mensaje-aqui"

    # Clave AES de 256 bits (32 bytes)
    key = os.urandom(32)

    # Cifrar el mensaje
    encrypted_data = encrypt_message(message, key)
    print("Mensaje cifrado:", encrypted_data.hex())

    # Extraer IV y texto cifrado del mensaje cifrado
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Descifrar el mensaje
    decrypted_message = decrypt_message(ciphertext, key, iv)
    print("Mensaje descifrado:", decrypted_message.decode())

if __name__ == "__main__":
    main()
