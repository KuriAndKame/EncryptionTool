from Crypto.Cipher import Salsa20
from PIL import Image
import numpy as np
import os
import time
import hashlib

def salsa20_encrypt_image(filepath, destination_path, salsa20_key):
    """
    Шифрует изображение с использованием Salsa20 (без использования pad/unpad).
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        salsa20_key (bytes): 32-байтовый ключ Salsa20.
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    

    # Инициализация Salsa20
    cipher = Salsa20.new(key=salsa20_key)
    nonce = cipher.nonce

    # Шифрование данных
    encrypted_pixels = cipher.encrypt(flat_pixels.tobytes())

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_Salsa20.png'))

    # Сохранение nonce для расшифровки
    with open(os.path.join(destination_path, 'nonce.bin'), 'wb') as nonce_file:
        nonce_file.write(nonce)

    elapsed_time = time.perf_counter() - start_time
    print(f"Salsa20 encryption time: {elapsed_time:0.4f} seconds")


def salsa20_decrypt_image(filepath, nonce_path, destination_path, salsa20_key):
    """
    Расшифровывает изображение, зашифрованное с использованием Salsa20 (без использования unpad).
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        salsa20_key (bytes): 32-байтовый ключ Salsa20.
    """
    start_time = time.perf_counter()

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    with open(nonce_path, 'rb') as nonce_file:
        nonce = nonce_file.read()

    # Инициализация Salsa20
    cipher = Salsa20.new(key=salsa20_key, nonce=nonce)

    # Расшифровка данных
    decrypted_pixels = cipher.decrypt(flat_encrypted_pixels.tobytes())

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = np.frombuffer(decrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_Salsa20.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"Salsa20 decryption time: {elapsed_time:0.4f} seconds")


def string_to_salsa20_key(input_string: str) -> bytes:
    """
    Преобразует строку в ключ для Salsa20.
    
    Args:
        input_string (str): Исходная строка.
    
    Returns:
        bytes: Сгенерированный ключ длиной 32 байта.
    """
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ длиной 32 байта
    return hash_digest[:32]
