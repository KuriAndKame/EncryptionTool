from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from PIL import Image
import numpy as np
import os
import time


def rsa_encrypt_image(filepath, destination_path, public_key_path, aes_key):
    """
    Шифрует изображение с использованием RSA и AES (гибридный подход).
    
    Args:
        filepath (str): Путь к исходному изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        public_key_path (str): Путь к открытому RSA-ключу (PEM формат).
        aes_key (bytes): AES-ключ для шифрования изображения (должен быть 16 байт).
    """
    start_time = time.perf_counter()

    # Загрузка открытого ключа
    with open(public_key_path, "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())

    # Шифрование AES-ключа с использованием RSA
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Инициализация AES для шифрования данных изображения
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    padding_length = (16 - len(flat_pixels) % 16) % 16
    flat_pixels_padded = np.pad(flat_pixels, (0, padding_length), mode='constant', constant_values=0)
    encrypted_pixels = aes_cipher.encrypt(flat_pixels_padded.tobytes())

    # Сохранение зашифрованного изображения
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8)[:len(flat_pixels)].reshape((height, width, 3))
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_RSA_AES.png'))

    # Сохранение зашифрованного AES-ключа
    with open(os.path.join(destination_path, 'encrypted_aes_key.bin'), 'wb') as key_file:
        key_file.write(encrypted_aes_key)

    elapsed_time = time.perf_counter() - start_time
    print(f"RSA-AES encryption time: {elapsed_time:.4f} seconds")


def rsa_decrypt_image(filepath, destination_path, private_key_path, encrypted_aes_key_path):
    """
    Расшифровывает изображение, зашифрованное с использованием RSA и AES.
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        private_key_path (str): Путь к закрытому RSA-ключу (PEM формат).
        encrypted_aes_key_path (str): Путь к зашифрованному AES-ключу.
    """
    start_time = time.perf_counter()

    # Загрузка закрытого ключа
    with open(private_key_path, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())

    # Загрузка и расшифровка AES-ключа
    rsa_cipher = PKCS1_OAEP.new(private_key)
    with open(encrypted_aes_key_path, 'rb') as key_file:
        encrypted_aes_key = key_file.read()
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Инициализация AES для расшифровки данных изображения
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_pixels = aes_cipher.decrypt(flat_encrypted_pixels.tobytes())
    decrypted_pixels = np.frombuffer(decrypted_pixels, dtype=np.uint8)[:len(flat_encrypted_pixels)]

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = decrypted_pixels.reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_RSA_AES.png'))

    elapsed_time = time.perf_counter() - start_time
    print(f"RSA-AES decryption time: {elapsed_time:.4f} seconds")
