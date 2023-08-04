# -*- coding: utf-8 -*-
from cryptography.fernet import Fernet
from django.shortcuts import render, HttpResponse
from encryption_Decryption.models import EncryptedText, DecryptedText

import binascii

# Create your views here.

def encrypt(request):
    if request.method == 'POST':
        plain_text = str(request.POST.get('plain_text'))
        algorithm = str(request.POST.get('algorithm'))
        key = str(Fernet.generate_key().decode())

        # Implementing encryption based on algorithm
        # For Fernet
        if algorithm == 'fernet':
            cipher_suite = Fernet(key)
            encrypted_text = cipher_suite.encrypt(plain_text.encode()).decode()

            # Save the encrypted data to the database
            EncryptedText.objects.create(
                plain_text=plain_text,
                encrypted_text=encrypted_text,
                algorithm=algorithm,
                key=key
            )
            print("Fernet runned successfully")

            return render(request, 'encryption.html', {
                'encrypted_text': str(encrypted_text),
                'algorithm': algorithm,
                'key':str(key)
            })

        # AES Algorithm
        if algorithm == 'aes':
            print("AES Algorithm")

        # Triple DES
        if algorithm == 'des':
            print("Triple DES Algorithm")

        # Blowfish
        if algorithm == 'blowfish':
            print("Blowfish Algorithm")

        # RSA
        if algorithm == 'rsa':

            """return render(request, 'encryption.html',{
                'encrypted_text': str(encrypted_message),
                'algorithm': algorithm,
                'key': str(key)
            })"""

        # caesar cipher text
        if algorithm == 'caesar':
            print("Caesar Cipher Algorithm")

        # TwoFish
        if algorithm == 'twofish':
            print("Twofish Algorithm")

        elif algorithm == 'cipher':
            print("This is cipher")

    return render(request, 'encryption.html')


def decrypt(request):
    # Taking the post request
    if request.method == 'POST':
        decrypted_text = str(request.POST.get('cipher_text'))
        algorithm = str(request.POST.get('algorithm'))
        key = str(request.POST.get('key'))

        # Implementing decryption based on algorithm
        # Fernet Algorithm
        if algorithm == 'fernet':
            cipher_suite = Fernet(key)
            decrypt_text = cipher_suite.decrypt(decrypted_text.encode()).decode()
            key=str(key)

            DecryptedText.objects.create(
                decrypted_text=decrypted_text,
                key=key,
                algorithm=algorithm,
            )

            

            return render(request, 'decryption.html', {
                'decrypted_text': str(decrypt_text),
                'algorithm': algorithm
            })

        # AES Algorithm
        if algorithm == 'aes':
            print("AES Algorithm")

        # Triple DES
        if algorithm == 'des':
            print("Triple DES Algorithm")

        # Blowfish
        if algorithm == 'blowfish':
            print("Blowfish Algorithm")

        # RSA
        if algorithm == 'rsa':
            """return render(request, 'decryption.html', {
                'decrypted_text': str(decrypt_text),
                'algorithm': algorithm
            })"""

        # caesar cipher text
        if algorithm == 'caesar':
            print("Caesar Cipher Algorithm")


        # TwoFish
        if algorithm == 'twofish':
            print("Twofish Algorithm")

    return render(request, 'decryption.html')