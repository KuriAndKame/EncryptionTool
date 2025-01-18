from serpent import serpant
from PIL import Image
import numpy as np
import os
import time
import hashlib


def serpent_encrypt_image(filepath, destination_path, key):
    """
    Шифрует изображение с использованием Serpent.

    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Папка для сохранения зашифрованного изображения.
        key (str): Ключ (строка, преобразуется в байты).
    """
    start_time = time.perf_counter()

    # Инициализация Serpent
    cipher = serpant(key)

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Паддинг для кратности длине блока (16 байт)
    block_size = 16
    padding_length = (block_size - (len(flat_pixels) % block_size)) % block_size
    flat_pixels_padded = np.pad(flat_pixels, (0, padding_length), mode='constant', constant_values=0)

    # Шифрование блоков
    encrypted_pixels = b""
    for i in range(0, len(flat_pixels_padded), block_size):
        block = bytes(flat_pixels_padded[i:i+block_size])
        encrypted_pixels += cipher.encrypt(block)

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8)[:len(flat_pixels)].reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_Serpent.png'))

    elapsed_time = time.perf_counter() - start_time
    print(f"Serpent encryption time: {elapsed_time:.4f} seconds")


def serpent_decrypt_image(filepath, destination_path, key):
    """
    Расшифровывает изображение, зашифрованное с использованием Serpent.

    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Папка для сохранения расшифрованного изображения.
        key (str): Ключ (строка, преобразуется в байты).
    """
    start_time = time.perf_counter()

    # Инициализация Serpent
    cipher = serpant(key)

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Расшифровка блоков
    decrypted_pixels = b""
    for i in range(0, len(flat_encrypted_pixels), 16):
        block = bytes(flat_encrypted_pixels[i:i+16])
        decrypted_pixels += cipher.decrypt(block)

    decrypted_pixels = np.frombuffer(decrypted_pixels, dtype=np.uint8)[:len(flat_encrypted_pixels)]

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = decrypted_pixels.reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_Serpent.png'))

    elapsed_time = time.perf_counter() - start_time
    print(f"Serpent decryption time: {elapsed_time:.4f} seconds")


def string_to_serpent_key(input_string: str) -> str:
    """
    Преобразует строку в ключ для Serpent.

    Args:
        input_string (str): Исходная строка.

    Returns:
        str: Сгенерированный ключ в шестнадцатеричном формате.
    """
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).hexdigest()
    return hash_digest[:32]  # Используем только первые 32 символа (16 байт)

