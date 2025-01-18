from Crypto.Cipher import DES
import numpy as np
import time
from PIL import Image
import os
import hashlib

def des_encrypt_image(filepath, destination_path, des_key):
    # Загрузка изображения
    start_time = time.perf_counter()
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)
    
    # Преобразование изображения в байты
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()
    padded_size = (len(flat_pixels) + 7) // 8 * 8  # Размер кратен 8 байтам
    padded_pixels = np.pad(flat_pixels, (0, padded_size - len(flat_pixels)), 'constant', constant_values=0)
    
    # Инициализация DES
    cipher = DES.new(des_key, DES.MODE_ECB)
    
    # Шифрование блоков
    encrypted_pixels = bytearray()
    for i in range(0, len(padded_pixels), 8):
        block = bytes(padded_pixels[i:i+8])
        encrypted_pixels.extend(cipher.encrypt(block))
    
    # Восстановление зашифрованного изображения
    encrypted_pixels = np.array(list(encrypted_pixels[:len(flat_pixels)]), dtype=np.uint8)
    encrypted_image = encrypted_pixels.reshape((height, width, 3))
    
    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_DES.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"DES encryption time: {elapsed_time:0.4f} seconds")
    


def des_decrypt_image(filepath, destination_path, des_key):
    # Загрузка зашифрованного изображения
    start_time = time.perf_counter()
    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)
    
    # Преобразование в байты
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()
    padded_size = (len(flat_encrypted_pixels) + 7) // 8 * 8
    padded_encrypted_pixels = np.pad(flat_encrypted_pixels, (0, padded_size - len(flat_encrypted_pixels)), 'constant', constant_values=0)
    
    # Инициализация DES
    cipher = DES.new(des_key, DES.MODE_ECB)
    
    # Расшифровка блоков
    decrypted_pixels = bytearray()
    for i in range(0, len(padded_encrypted_pixels), 8):
        block = bytes(padded_encrypted_pixels[i:i+8])
        decrypted_pixels.extend(cipher.decrypt(block))
    
    # Восстановление расшифрованного изображения
    decrypted_pixels = np.array(list(decrypted_pixels[:len(flat_encrypted_pixels)]), dtype=np.uint8)
    decrypted_image = decrypted_pixels.reshape((height, width, 3))
    
    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_DES.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"DES encryption time: {elapsed_time:0.4f} seconds")


def string_to_des_key_hash(input_string: str) -> bytes:
    """
    Преобразует строку в 8-байтовый DES-ключ с использованием хэширования.
    
    Args:
        input_string (str): Исходная строка.
    
    Returns:
        bytes: 8-байтовый DES-ключ.
    """
    # Используем SHA-256 для генерации хэша
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()

    # Возвращаем первые 8 байт хэша
    return hash_digest[:8]