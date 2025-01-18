import os
import cv2
import Image as i
import time
import encrypt as e
import des as ds
import blowfish as blf
import AES as aes
import arcfour as af
import cast5 as c5
import ChaCha20 as chacha
import Salsa20 as salsa
import GOST28147 as gost
import camelia as cam
import TwoFish as twf
#import Serpent as ser
import SEED as sd
from PIL import Image as img

def decrypt(filepath, destination_path, key, method, Rubik_key_path=None, affine_key_entry_a = None, affine_key_entry_b = None):
    
    match method:
        case 'Arcfour':
            arcfour_key = af.string_to_rc4_key(str(key.public_key))
            af.rc4_decrypt_image(filepath, destination_path, arcfour_key)
        case 'DES':
            des_key = ds.string_to_des_key_hash(str(key.public_key))
            ds.des_decrypt_image(filepath,destination_path, des_key)
        case 'Blowfish':
            blowfish_key = blf.string_to_blowfish_key(str(key.public_key))
            blf.blowfish_decrypt_image(filepath, destination_path, blowfish_key)
        case 'AES':
            aes_key = aes.string_to_aes_key(str(key.public_key))
            aes.aes_decrypt_image(filepath, destination_path, aes_key)
        case 'CAST5':
            cast5_key = c5.string_to_cast5_key(str(key.public_key))
            c5.cast5_decrypt_image(filepath, destination_path, cast5_key)
        case 'ChaCha20':
            chacha20_key = chacha.string_to_chacha20_key((str(key.public_key)))
            nonce_path = os.path.join(destination_path, 'nonce.bin')
            chacha.chacha20_decrypt_image(filepath,nonce_path, destination_path, chacha20_key)
        case 'Salsa20':
            salsa_key = salsa.string_to_salsa20_key(str(key.public_key))
            nonce_path = os.path.join(destination_path, 'nonce.bin')
            salsa.salsa20_decrypt_image(filepath, nonce_path,destination_path, salsa_key)
        case 'GOST28147':
            gost_key = gost.string_to_gost_key(str(key.public_key))
            gost.gost_decrypt_image(filepath, destination_path, gost_key)
        case 'Camellia':
            camellia_key = cam.string_to_camellia_key(str(key.public_key))
            cam.camellia_decrypt_image(filepath, destination_path, camellia_key)
        case 'SEED':
            seed_key = sd.string_to_seed_key(str(key.public_key))
            sd.seed_decrypt_image(filepath, destination_path, seed_key)
        case 'Twofish':
            twofish_key = twf.string_to_twofish_key(str(key.public_key))
            twf.twofish_decrypt_image(filepath, destination_path, twofish_key)