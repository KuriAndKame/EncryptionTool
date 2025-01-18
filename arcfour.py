from Crypto.Cipher import ARC4
from PIL import Image
import numpy as np
import os
import time
import hashlib

def rc4_encrypt_image(filepath, destination_path, rc4_key):
    """
    Шифрует изображение с использованием RC4.
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        rc4_key (bytes): Ключ для RC4.
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Инициализация RC4
    cipher = ARC4.new(rc4_key)

    # Шифрование данных
    encrypted_pixels = cipher.encrypt(flat_pixels.tobytes())

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_RC4.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"RC4 encryption time: {elapsed_time:0.4f} seconds")


def rc4_decrypt_image(filepath, destination_path, rc4_key):
    """
    Расшифровывает изображение, зашифрованное с использованием RC4.
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        rc4_key (bytes): Ключ для RC4.
    """
    start_time = time.perf_counter()

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Инициализация RC4
    cipher = ARC4.new(rc4_key)

    # Расшифровка данных
    decrypted_pixels = cipher.decrypt(flat_encrypted_pixels.tobytes())

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = np.frombuffer(decrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_RC4.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"RC4 decryption time: {elapsed_time:0.4f} seconds")


def string_to_rc4_key(input_string: str) -> bytes:
    """
    Преобразует строку в ключ для RC4.
    
    Args:
        input_string (str): Исходная строка.
    
    Returns:
        bytes: Сгенерированный ключ.
    """
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ длиной 16 байт
    return hash_digest[:16]
