import os
import time
import gostcrypto
import numpy as np
import hashlib
from PIL import Image

def gost_encrypt_image(filepath, destination_path, gost_key):
    """
    Шифрует изображение с использованием ГОСТ 28147-89.
    
    Args:
        filepath (str): Путь к изображению.
        destination_path (str): Путь для сохранения зашифрованного изображения.
        gost_key (bytes): Ключ для ГОСТ 28147-89 (32 байта).
    """
    start_time = time.perf_counter()

    # Загрузка изображения
    image = Image.open(filepath).convert('RGB')
    pixels = np.array(image)

    # Преобразование изображения в одномерный массив
    height, width, _ = pixels.shape
    flat_pixels = pixels.flatten()

    # Инициализация ГОСТ 28147-89
    cipher = gostcrypto.gostcipher.new('kuznechik',gost_key,gostcrypto.gostcipher.MODE_ECB,
                                        pad_mode=gostcrypto.gostcipher.PAD_MODE_1)

    # Шифрование данных
    encrypted_pixels = cipher.encrypt(flat_pixels.tobytes())

    # Преобразование зашифрованных данных обратно в массив пикселей
    encrypted_image = np.frombuffer(encrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение зашифрованного изображения
    encrypted_image = Image.fromarray(encrypted_image, 'RGB')
    encrypted_image.save(os.path.join(destination_path, 'encrypted_GOST.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"GOST encryption time: {elapsed_time:0.4f} seconds")


def gost_decrypt_image(filepath, destination_path, gost_key):
    """
    Расшифровывает изображение, зашифрованное с использованием ГОСТ 28147-89.
    
    Args:
        filepath (str): Путь к зашифрованному изображению.
        destination_path (str): Путь для сохранения расшифрованного изображения.
        gost_key (bytes): Ключ для ГОСТ 28147-89 (32 байта).
    """
    start_time = time.perf_counter()

    encrypted_image = Image.open(filepath).convert('RGB')
    encrypted_pixels = np.array(encrypted_image)

    # Преобразование изображения в одномерный массив
    height, width, _ = encrypted_pixels.shape
    flat_encrypted_pixels = encrypted_pixels.flatten()

    # Инициализация ГОСТ 28147-89
    cipher = gostcrypto.gostcipher.new('kuznechik',gost_key,gostcrypto.gostcipher.MODE_ECB,
                                        pad_mode=gostcrypto.gostcipher.PAD_MODE_1)

    # Расшифровка данных
    decrypted_pixels = cipher.decrypt(flat_encrypted_pixels.tobytes())

    # Преобразование расшифрованных данных обратно в массив пикселей
    decrypted_image = np.frombuffer(decrypted_pixels, dtype=np.uint8).reshape((height, width, 3))

    # Сохранение расшифрованного изображения
    decrypted_image = Image.fromarray(decrypted_image, 'RGB')
    decrypted_image.save(os.path.join(destination_path, 'decrypted_GOST.png'))
    elapsed_time = time.perf_counter() - start_time
    print(f"GOST decryption time: {elapsed_time:0.4f} seconds")


def string_to_gost_key(input_string: str) -> bytes:
    """
    Преобразует строку в ключ для ГОСТ 28147-89.
    
    Args:
        input_string (str): Исходная строка.
    
    Returns:
        bytes: Сгенерированный ключ.
    """
    # Генерация хэша строки
    hash_digest = hashlib.sha256(input_string.encode('utf-8')).digest()
    
    # Возвращаем ключ длиной 32 байта (256 бит)
    return hash_digest[:32]
