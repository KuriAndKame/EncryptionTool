from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import numpy as np
from PIL import Image
import os
import time
import hashlib

def seed_encrypt_image(filepath, destination_path, seed_key):
    """
    Шифрует изображение с использованием SEED.
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        seed_key (bytes): Ключ для SEED (16 байт).
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Инициализация SEED
    cipher = Cipher(algorithms.SEED(seed_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Шифрование данных
    encrypted_pixels = encryptor.update(flat_pixels.tobytes()) + encryptor.finalize()

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_SEED.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"SEED encryption time: {elapsed_time:0.4f} seconds")


def seed_decrypt_image(filepath, destination_path, seed_key):
    """
    Расшифровывает изображение, зашифрованное с использованием SEED.
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        seed_key (bytes): Ключ для SEED (16 байт).
    """
    start_time = time.perf_counter()

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Инициализация SEED
    cipher = Cipher(algorithms.SEED(seed_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Расшифровка данных
    decrypted_pixels = decryptor.update(flat_encrypted_pixels.tobytes()) + decryptor.finalize()

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = np.frombuffer(decrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_SEED.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"SEED decryption time: {elapsed_time:0.4f} seconds")


def string_to_seed_key(input_string: str) -> bytes:
    """
    Преобразует строку в ключ для SEED.
    
    Args:
        input_string (str): Исходная строка.
    
    Returns:
        bytes: Сгенерированный ключ длиной 16 байт.
    """
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ длиной 16 байт
    return hash_digest[:16]
