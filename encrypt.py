import os
import cv2
import Image as i
import time
import Key as Key
import random
import des as ds
import blowfish as blf
import AES as aes
import arcfour as af
import cast5 as c5
import ChaCha20 as chacha
import GOST28147 as gost
import Salsa20 as salsa
import TwoFish as twf
import SEED as sd
import camelia as cam
from PIL import Image as img  
import RSA as rsa


def encrypt(filepath, destination_path, method,key, Rubik_key_path = None, affine_key_entry_a = None, affine_key_entry_b = None):
    match method:
        case 'Arcfour':
            arcfour_key = af.string_to_rc4_key((str(key.public_key)))
            keys_filepath = os.keys_filepath = os.path.join(destination_path, "Arcfour_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            af.rc4_encrypt_image(filepath, destination_path, arcfour_key)
        case 'DES':
            des_key = ds.string_to_des_key_hash(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "DES_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            ds.des_encrypt_image(filepath,destination_path, des_key)
        case 'Blowfish':
            blowfish_key = blf.string_to_blowfish_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "Blowfish_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            blf.blowfish_encrypt_image(filepath, destination_path, blowfish_key)
        case 'AES':
            aes_key = aes.string_to_aes_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "AES_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            aes.aes_encrypt_image(filepath, destination_path, aes_key)
        case 'CAST5':
            cast5_key = c5.string_to_cast5_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "CAST5_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            c5.cast5_encrypt_image(filepath, destination_path, cast5_key)
        case 'ChaCha20':
            chacha20_key = chacha.string_to_chacha20_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "ChaCha20_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            chacha.chacha20_encrypt_image(filepath, destination_path, chacha20_key)
        case 'Salsa20':
            salsa_key = salsa.string_to_salsa20_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "Salsa20_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            salsa.salsa20_encrypt_image(filepath, destination_path, salsa_key)
        case 'Camellia':
            camellia_key = cam.string_to_camellia_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "Camelia_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            cam.camellia_encrypt_image(filepath, destination_path, camellia_key)
        case 'GOST28147':
            gost_key = gost.string_to_gost_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "GOST28147_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            gost.gost_encrypt_image(filepath, destination_path, gost_key)
        case 'SEED':
            seed_key = sd.string_to_seed_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "SEED_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            sd.seed_encrypt_image(filepath, destination_path, seed_key)
        case 'Twofish':
            twofish_key = twf.string_to_twofish_key(str(key.public_key))
            keys_filepath = os.path.join(destination_path, "Twofish_key.txt")
            with open(keys_filepath, "w") as key_file:
                key_file.write(f"key: {key.public_key}\n")
            twf.twofish_encrypt_image(filepath, destination_path, twofish_key)
        case 'RSA':
           rsa.rsa_encrypt_image(filepath, destination_path, key.public_key, aes.string_to_aes_key(str(key.public_key)))
