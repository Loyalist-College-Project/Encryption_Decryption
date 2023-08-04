# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# Create your models here.
# encryption_Decryption/models.py
from django.db import models


class EncryptedText(models.Model):
    id = models.AutoField(primary_key=True)
    plain_text = models.CharField(max_length=500)
    encrypted_text = models.CharField(max_length=500)
    algorithm = models.CharField(max_length=50)
    key = models.CharField(max_length=100)


class DecryptedText(models.Model):
    id = models.AutoField(primary_key=True)
    cipher_text = models.CharField(max_length=50)
    key = models.CharField(max_length=50)
    decrypted_text = models.CharField(max_length=50)
    algorithm = models.CharField(max_length=50)