from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import os
import time
import hashlib

def chacha20_encrypt_image(filepath, destination_path, chacha20_key):
    """
    Шифрует изображение с использованием ChaCha20.
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        chacha20_key (bytes): Ключ для ChaCha20.
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Инициализация ChaCha20
    cipher = ChaCha20.new(key=chacha20_key)
    nonce = cipher.nonce

    # Шифрование данных
    encrypted_pixels = cipher.encrypt(flat_pixels.tobytes())

    # Сохранение зашифрованного изображения
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8).reshape((height, width, 3))
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_ChaCha20.png'))

    # Сохранение nonce для расшифровки
    with open(os.path.join(destination_path, 'nonce.bin'), 'wb') as nonce_file:
        nonce_file.write(nonce)

    elapsed_time = time.perf_counter() - start_time
    print(f"ChaCha20 encryption time: {elapsed_time:0.4f} seconds")


def chacha20_decrypt_image(filepath, nonce_path, destination_path, chacha20_key):
    """
    Расшифровывает изображение, зашифрованное с использованием ChaCha20.
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        nonce_path (str): Путь к файлу с nonce.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        chacha20_key (bytes): Ключ для ChaCha20.
    """
    start_time = time.perf_counter()

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Загрузка nonce
    with open(nonce_path, 'rb') as nonce_file:
        nonce = nonce_file.read()

    # Инициализация ChaCha20
    cipher = ChaCha20.new(key=chacha20_key, nonce=nonce)

    # Расшифровка данных
    decrypted_pixels = cipher.decrypt(flat_encrypted_pixels.tobytes())
    decrypted_image = np.frombuffer(decrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_ChaCha20.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"ChaCha20 decryption time: {elapsed_time:0.4f} seconds")


def string_to_chacha20_key(input_string: str) -> bytes:
    """
    Преобразует строку в ключ для ChaCha20.
    
    Args:
        input_string (str): Исходная строка.
    
    Returns:
        bytes: Сгенерированный ключ.
    """
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ длиной 32 байта
    return hash_digest[:32]
