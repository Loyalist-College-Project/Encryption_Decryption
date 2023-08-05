# -*- coding: utf-8 -*-
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish
from django.shortcuts import render
from encryption_Decryption.models import EncryptedText, DecryptedText
from django.shortcuts import render
import os

# Create your views here.

def encrypt(request):
    if request.method == 'POST':
        plain_text = str(request.POST.get('plain_text'))
        algorithm = str(request.POST.get('algorithm'))

        # Implementing encryption based on algorithm

        # AES Algorithm - Krish
        if algorithm == 'aes':
            key = str(Fernet.generate_key().decode())
            cipher_suite = Fernet(key)
            encrypted_text = cipher_suite.encrypt(plain_text.encode()).decode()

            # Save the encrypted data to the database
            EncryptedText.objects.create(
                plain_text=plain_text,
                encrypted_text=encrypted_text,
                algorithm=algorithm,
                key=key
            )

            return render(request, 'encryption.html', {
                'encrypted_text': str(encrypted_text),
                'algorithm': algorithm,
                'key': str(key)
            })

        # Triple DES - Bhumi, Vidhi and dheeraj
        if algorithm == 'des':
            print("Blowfish Algorithm")

        # Blowfish -
        if algorithm == 'blowfish':
            """"
            return render(request, 'encryption.html', {
                'encrypted_text': str(encrypted_text),
                'algorithm': algorithm,
                'key': str(key)
            })"""


        # RSA -
        if algorithm == 'rsa':
            """"
            return render(request, 'encryption.html', {
                'encrypted_text': str(encrypted_text),
                'algorithm': algorithm,
                'key': str(shift)
            })"""

        # caesar cipher text - Harsh
        if algorithm == 'caesar':
            """"
            return render(request, 'encryption.html', {
                'encrypted_text': str(encrypted_text),
                'algorithm': algorithm,
                'key': str(shift)
            })"""

    return render(request, 'encryption.html')


def decrypt(request):
    # Taking the post request
    if request.method == 'POST':
        decrypted_text = str(request.POST.get('cipher_text'))
        algorithm = str(request.POST.get('algorithm'))
        key = str(request.POST.get('key'))

        # Implementing decryption based on algorithm
        # AES Algorithm - Krish
        if algorithm == 'aes':
            cipher_suite = Fernet(key)
            decrypt_text = cipher_suite.decrypt(decrypted_text.encode()).decode()
            key = str(key)

            DecryptedText.objects.create(
                decrypted_text=decrypted_text,
                key=key,
                algorithm=algorithm,
            )

            return render(request, 'decryption.html', {
                'decrypted_text': str(decrypt_text),
                'algorithm': algorithm
            })

        # Triple DES - Bhumi, Vidhi and dheeraj
        if algorithm == 'des':
            print("Triple DES Algorithm")

        # Blowfish -
        if algorithm == 'blowfish':
            print("Blowfish Algorithm")

        # RSA -
        if algorithm == 'rsa':
            """"
            return render(request, 'decryption.html', {
                'decrypted_text': str(decrypt_text),
                'algorithm': algorithm
            })"""

        # caesar cipher text - Harsh
        if algorithm == 'caesar':
            print("Caesar Cipher")
            """"
            return render(request, 'decryption.html', {
                'decrypted_text': str(decrypt_text),
                'algorithm': algorithm
            })"""


    return render(request, 'decryption.html')
