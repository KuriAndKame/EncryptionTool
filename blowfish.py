from Crypto.Cipher import Blowfish
from PIL import Image
import numpy as np
import os
import time
import hashlib

def blowfish_encrypt_image(filepath, destination_path, blowfish_key):
    """
    Шифрует изображение с использованием Blowfish (без использования pad/unpad).
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        blowfish_key (bytes): Ключ длиной от 4 до 56 байт.
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразуем изображение в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Дополнение данных вручную до размера, кратного 8 байтам
    padded_size = (len(flat_pixels) + 7) // 8 * 8  # Размер кратен 8
    padded_pixels = np.pad(flat_pixels, (0, padded_size - len(flat_pixels)), 'constant', constant_values=0)

    # Инициализация Blowfish
    cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)

    # Шифрование данных блоками по 8 байт
    encrypted_pixels = bytearray()
    for i in range(0, len(padded_pixels), 8):
        block = bytes(padded_pixels[i:i+8])
        encrypted_pixels.extend(cipher.encrypt(block))

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_pixels = np.array(encrypted_pixels[:len(flat_pixels)], dtype=np.uint8)
    encrypted_image = encrypted_pixels.reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_blowfish.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"Blowfish encryption time: {elapsed_time:0.4f} seconds")


def blowfish_decrypt_image(filepath, destination_path, blowfish_key):
    """
    Расшифровывает изображение, зашифрованное с использованием Blowfish (без использования unpad).
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        blowfish_key (bytes): Ключ длиной от 4 до 56 байт.
    """
    start_time = time.perf_counter()

    # Загрузка зашифрованного изображения
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразуем пиксели в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Дополнение данных вручную до размера, кратного 8 байтам
    padded_size = (len(flat_encrypted_pixels) + 7) // 8 * 8  # Размер кратен 8
    padded_encrypted_pixels = np.pad(flat_encrypted_pixels, (0, padded_size - len(flat_encrypted_pixels)), 'constant', constant_values=0)

    # Инициализация Blowfish
    cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)

    # Расшифровка данных блоками по 8 байт
    decrypted_pixels = bytearray()
    for i in range(0, len(padded_encrypted_pixels), 8):
        block = bytes(padded_encrypted_pixels[i:i+8])
        decrypted_pixels.extend(cipher.decrypt(block))

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_pixels = np.array(decrypted_pixels[:len(flat_encrypted_pixels)], dtype=np.uint8)
    decrypted_image = decrypted_pixels.reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_blowfish.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"Blowfish decryption time: {elapsed_time:0.4f} seconds")




def string_to_blowfish_key(input_string: str, key_length: int = 16) -> bytes:
    """
    Преобразует строку в ключ для Blowfish.
    
    Args:
        input_string (str): Исходная строка.
        key_length (int): Длина ключа (от 4 до 56 байт).
    
    Returns:
        bytes: Сгенерированный ключ длиной key_length байт.
    """
    if not (4 <= key_length <= 56):
        raise ValueError("Длина ключа должна быть от 4 до 56 байт.")
    
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ нужной длины
    return hash_digest[:key_length]
