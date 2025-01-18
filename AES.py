from Crypto.Cipher import AES
from PIL import Image
import numpy as np
import os
import time
import hashlib

def aes_encrypt_image(filepath, destination_path, aes_key):
    """
    Шифрует изображение с использованием AES (без использования pad/unpad).
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        aes_key (bytes): 16/24/32-байтовый ключ AES.
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Дополнение данных вручную до размера, кратного 16 байтам
    padded_size = (len(flat_pixels) + 15) // 16 * 16  # Размер кратен 16
    padded_pixels = np.pad(flat_pixels, (0, padded_size - len(flat_pixels)), 'constant', constant_values=0)

    # Инициализация AES
    cipher = AES.new(aes_key, AES.MODE_ECB)

    # Шифрование данных блоками по 16 байт
    encrypted_pixels = bytearray()
    for i in range(0, len(padded_pixels), 16):
        block = bytes(padded_pixels[i:i+16])
        encrypted_pixels.extend(cipher.encrypt(block))

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_pixels = np.array(encrypted_pixels[:len(flat_pixels)], dtype=np.uint8)
    encrypted_image = encrypted_pixels.reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_AES.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"AES encryption time: {elapsed_time:0.4f} seconds")


def aes_decrypt_image(filepath, destination_path, aes_key):
    """
    Расшифровывает изображение, зашифрованное с использованием AES (без использования unpad).
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        aes_key (bytes): 16/24/32-байтовый ключ AES.
    """
    start_time = time.perf_counter()

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Дополнение данных вручную до размера, кратного 16 байтам
    padded_size = (len(flat_encrypted_pixels) + 15) // 16 * 16
    padded_encrypted_pixels = np.pad(flat_encrypted_pixels, (0, padded_size - len(flat_encrypted_pixels)), 'constant', constant_values=0)

    # Инициализация AES
    cipher = AES.new(aes_key, AES.MODE_ECB)

    # Расшифровка данных блоками по 16 байт
    decrypted_pixels = bytearray()
    for i in range(0, len(padded_encrypted_pixels), 16):
        block = bytes(padded_encrypted_pixels[i:i+16])
        decrypted_pixels.extend(cipher.decrypt(block))

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_pixels = np.array(decrypted_pixels[:len(flat_encrypted_pixels)], dtype=np.uint8)
    decrypted_image = decrypted_pixels.reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_AES.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"AES decryption time: {elapsed_time:0.4f} seconds")



def string_to_aes_key(input_string: str, key_length: int = 16) -> bytes:
    """
    Преобразует строку в ключ для AES.
    
    Args:
        input_string (str): Исходная строка.
        key_length (int): Длина ключа для AES (16, 24, 32 байта).
    
    Returns:
        bytes: Сгенерированный ключ длиной key_length байт.
    """
    if key_length not in [16, 24, 32]:
        raise ValueError("Длина ключа должна быть 16, 24 или 32 байта.")
    
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ нужной длины
    return hash_digest[:key_length]