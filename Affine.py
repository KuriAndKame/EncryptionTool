import cv2 
import math
import numpy as np
import random

class Affine:
    def __init__(self, a, b, m ):
        self.a = a
        self.b = b
        self.m = m
        while self.IsCoprime() is False:
            print(a," and ",m," Must be Coprime! ")
            a,m = map(int,input("Enter a and m (Seperated by single space): ").split(" "))
            self.a = a
            self.m = m
        self.inv_a =  self.ModInv()

    def IsCoprime(self):
        """
        Check whether a and m is prime or not. If it is prime then it return true else false
        """
        if math.gcd(self.a, self.m) == 1:
            return True
        return False

    def ModInv(self):
        """
        Form equation 1 = inv(a)*a mod m. we find inv(a)
        Inverse exist only if a and m be Coprime
        """
        for i in range(2,self.m):
            if (self.a * i) % self.m == 1 :
                return i
        return 1
 
    def E(self, x):
        """
        m is the length of range. a and b are the Keys of the cipher.
        The value a must be chosen such that a and are coprime.
        """
        
        return (self.a*x + self.b) % self.m

    def D(self,y):
        """
        Decryption at pixel level
        """
        return (self.inv_a * (y-self.b)) % self.m

    def encryption(self, original_img, destination_path):
        """
        Encryption of image 
        """
        original_img = original_img.astype('int') 
        height, width, _ = original_img.shape
    
        encrypted_img = original_img.copy()
    
        for i in range(height):
            for j in range(width):
                r, g, b = encrypted_img[i, j]
                r = self.E(r)
                g = self.E(g)
                b = self.E(b)
                encrypted_img[i, j] = [r, g, b]
    
        
        encrypted_img = encrypted_img.astype('uint8')
        cv2.imwrite(destination_path + '/encryptedAffine.png', encrypted_img)


    def decryption(self, encry_img, destination_path):
        """
        Decryption of image 
        """
        encry_img = encry_img.astype('int')  
        height, width, _ = encry_img.shape

        decrypted_img = encry_img.copy()  

        for i in range(height):
            for j in range(width):
                r, g, b = decrypted_img[i, j]
                r = self.D(r)
                g = self.D(g)
                b = self.D(b)
                decrypted_img[i, j] = [r, g, b]

        
        decrypted_img = decrypted_img.astype('uint8')
        cv2.imwrite(destination_path + '/decryptedAffine.png', decrypted_img)  

