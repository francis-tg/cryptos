from cryptography.hazmat.primitives import  padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib

def generate_aes_key(key):
    # Convertir la clé en bytes
    key_bytes = key.encode()

    # Utiliser SHA-256 pour générer une empreinte de 256 bits
    sha256 = hashlib.sha256()
    sha256.update(key_bytes)
    digest = sha256.digest()

    # Prendre les 16 premiers octets de l'empreinte pour obtenir une clé de 128 bits
    aes_key = digest[:16]
    
    return aes_key
def encrypt_message(message, key):
    # Convertir la clé en bytes
    key_bytes = generate_aes_key(key)

    # Vérifier et ajuster la taille de la clé à 128 bits si nécessaire
    if len(key_bytes) != 16:
        raise ValueError("La clé doit être de 128 bits (16 octets).")
    
    # Initialiser le mode CBC avec un vecteur d'initialisation aléatoire
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())

    # Créer le chiffreur
    encryptor = cipher.encryptor()

    # Appliquer le padding PKCS7 au message
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Chiffrer le message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Retourner le message chiffré et le vecteur d'initialisation
    return encrypted_message, iv

def decrypt_message(encrypted_message, iv, key):
    # Convertir la clé en bytes
    key_bytes = generate_aes_key(key)

    # Vérifier et ajuster la taille de la clé à 128 bits si nécessaire
    if len(key_bytes) != 16:
        raise ValueError("La clé doit être de 128 bits (16 octets).")

    # Initialiser le mode CBC avec le vecteur d'initialisation fourni
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())

    # Créer le déchiffreur
    decryptor = cipher.decryptor()

    # Déchiffrer le message
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Retirer le padding PKCS7 du message déchiffré
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    # Retourner le message déchiffré
    return unpadded_message.decode()

# Message clair
message = "ISTA, INSTITUTE OF ART AND TECHNOLOGY"

# Clé de chiffrement
key = "SECRETKEY12345678"

# Chiffrer le message
encrypted_message, iv = encrypt_message(message, key)
print(f"Message chiffré (hex) : {encrypted_message.hex()}")

# Déchiffrer le message
decrypted_message = decrypt_message(encrypted_message, iv, key)
print(f"Message déchiffré : {decrypted_message}")
