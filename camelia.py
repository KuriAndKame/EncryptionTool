from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
from PIL import Image
import numpy as np
import os
import time
import hashlib

def camellia_encrypt_image(filepath, destination_path, camellia_key):
    """
    Шифрует изображение с использованием Camellia.
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        camellia_key (bytes): Ключ для Camellia (16, 24 или 32 байта).
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Инициализация Camellia
    cipher = Cipher(algorithms.Camellia(camellia_key), modes.ECB())
    encryptor = cipher.encryptor()

    # Шифрование данных
    encrypted_pixels = encryptor.update(flat_pixels.tobytes()) + encryptor.finalize()
    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    #with open(os.path.join(destination_path, 'iv.txt'), 'wb') as nonce_file:
     #   nonce_file.write(iv)

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_Camellia.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"Camellia encryption time: {elapsed_time:0.4f} seconds")


def camellia_decrypt_image(filepath, destination_path, camellia_key):
    """
    Расшифровывает изображение, зашифрованное с использованием Camellia.
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        camellia_key (bytes): Ключ для Camellia (16, 24 или 32 байта).
    """
    start_time = time.perf_counter()

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    #with open(iv_path, 'rb') as nonce_file:
     #   nonce = nonce_file.read()

    # Инициализация Camellia
    cipher = Cipher(algorithms.Camellia(camellia_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Расшифровка данных
    decrypted_pixels = decryptor.update(flat_encrypted_pixels.tobytes()) + decryptor.finalize()

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = np.frombuffer(decrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_Camellia.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"Camellia decryption time: {elapsed_time:0.4f} seconds")


def string_to_camellia_key(input_string: str, key_length: int = 16) -> bytes:
    """
    Преобразует строку в ключ для Camellia.
    
    Args:
        input_string (str): Исходная строка.
        key_length (int): Длина ключа для Camellia (16, 24, 32 байта).
    
    Returns:
        bytes: Сгенерированный ключ длиной key_length байт.
    """
    if key_length not in [16, 24, 32]:
        raise ValueError("Длина ключа должна быть 16, 24 или 32 байта.")
    
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ нужной длины
    return hash_digest[:key_length]


