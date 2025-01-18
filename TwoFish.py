from twofish import Twofish
from PIL import Image
import numpy as np
import os
import time
import hashlib


def twofish_encrypt_image(filepath, destination_path, twofish_key):
    """
    Шифрует изображение с использованием Twofish.
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        twofish_key (bytes): Ключ для Twofish.
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Паддинг для кратности блока (16 байт)
    block_size = 16
    padding_length = (block_size - (len(flat_pixels) % block_size)) % block_size
    flat_pixels_padded = np.pad(flat_pixels, (0, padding_length), mode='constant', constant_values=0)

    # Инициализация Twofish
    cipher = Twofish(twofish_key)

    # Шифрование данных блоками
    encrypted_pixels = b""
    for i in range(0, len(flat_pixels_padded), block_size):
        block = flat_pixels_padded[i:i + block_size].tobytes()
        encrypted_pixels += cipher.encrypt(block)

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8)[:len(flat_pixels)].reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_Twofish.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"Twofish encryption time: {elapsed_time:0.4f} seconds")


def twofish_decrypt_image(filepath, destination_path, twofish_key):
    """
    Расшифровывает изображение, зашифрованное с использованием Twofish.
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        twofish_key (bytes): Ключ для Twofish.
    """
    start_time = time.perf_counter()

    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Паддинг для кратности блока (16 байт)
    block_size = 16
    padding_length = (block_size - (len(flat_encrypted_pixels) % block_size)) % block_size
    flat_encrypted_pixels_padded = np.pad(flat_encrypted_pixels, (0, padding_length), mode='constant', constant_values=0)

    # Инициализация Twofish
    cipher = Twofish(twofish_key)

    # Расшифровка данных блоками
    decrypted_pixels = b""
    for i in range(0, len(flat_encrypted_pixels_padded), block_size):
        block = flat_encrypted_pixels_padded[i:i + block_size].tobytes()
        decrypted_pixels += cipher.decrypt(block)

    decrypted_pixels = np.frombuffer(decrypted_pixels, dtype=np.uint8)[:len(flat_encrypted_pixels)]

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = decrypted_pixels.reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_Twofish.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"Twofish decryption time: {elapsed_time:0.4f} seconds")


def string_to_twofish_key(input_string: str) -> bytes:
    """
    Преобразует строку в ключ для Twofish.
    
    Args:
        input_string (str): Исходная строка.
    
    Returns:
        bytes: Сгенерированный ключ длиной 16 байт.
    """
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ длиной 16 байт
    return hash_digest[:16]
