# password_generator/views.py
from django.shortcuts import render
import random
import string
from .models import *
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import hashlib
from .forms import CreateUserFrom, PassFrom
import traceback
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os

# Specify the folder where you want to save the key
key_folder = r"D:\programming\tugas PBO\python-password-generator\password_generator_project\private_key_folder"



def registerPage(request):
    form = CreateUserFrom()

    if request.method == 'POST':
        form = CreateUserFrom(request.POST)
        if form.is_valid(): 
            form.save()
            user = form.cleaned_data.get('username')
            messages.success(request, 'Account was created for' + user)
            return redirect('login')

    context = {'form': form}
    return render(request, 'password_generator/register.html', context )

def loginPage(request):

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('generate_password')  
        else:
            messages.info(request, 'Username OR Password is incorrect')

    context = {}
    return render(request, 'password_generator/login.html', context )

def logoutUser(request):
    logout(request)
    return redirect('login')


@login_required(login_url='login')
def encrypt(request):
    if request.method == 'POST':
        plaintext = request.POST.get('length', '').encode()

        # Generate an RSA key pair (public and private keys)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Get the public key for encryption
        public_key = private_key.public_key()

        # Serialize and save the public key to a file
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_key_path = r"D:\programming\tugas PBO\python-password-generator\password_generator_project\private_key_folder\public_key.pem"
        with open(public_key_path, "wb") as public_key_file:
            public_key_file.write(public_key_pem)

        # Serialize and save the private key to a file in the same folder as the public key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        private_key_path = os.path.join(os.path.dirname(public_key_path), "private_key.pem")
        with open(private_key_path, "wb") as private_key_file:
            private_key_file.write(private_key_pem)

        # Encrypt the data using the RSA public key
        encrypted_data = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

        #save the encrypted data to a file or do other processing
        key = str(private_key_pem)
        encrypted_hex = encrypted_data.hex()
        return render(request, 'password_generator/generate_password.html', {'password': encrypted_hex,'key':key})
    
    return render(request, 'password_generator/generate_password.html')

    

@login_required(login_url='login')
def decrypt(request):
    if request.method == 'POST':
        # Get the encrypted data from the form
        encrypted_data_hex = request.POST.get('length', '')

        # Load the private key from the specified path
        private_key_path = r"D:\programming\tugas PBO\python-password-generator\password_generator_project\private_key_folder\private_key.pem"
        with open(private_key_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None  # Replace with your private key password if you set one
            )

        try:
            # Convert the hexadecimal encrypted data back to bytes
            encrypted_data = bytes.fromhex(encrypted_data_hex)

            # Decrypt the data using the private key
            plaintext = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )

            # Convert the decrypted bytes to a string
            plaintext = plaintext.decode()

        except Exception as e:
            print(f"Decryption Error: {e}")
            plaintext = "Decryption Error"

        return render(request, 'password_generator/decrypt.html', {'plain': plaintext})

    return render(request, 'password_generator/decrypt.html')


def viewpassword(request):
    passname = Passname.objects.all()
    return render(request, 'password_generator/viewpassword.html', {'passname':passname})

def createPass(request):

    form = PassFrom()
    
    if request.method == 'POST':
        #print('printing POST:', request.POST)
        form = PassFrom(request.POST)
        if form.is_valid:
            form.save()
            return redirect('/')

    context = {'form':form}
    return render(request, "password_generator/update_form.html", context)

def updatePass(request):
    pas = Passname.objects.get(id) 
    form = PassFrom(instance=pas)
    context = {}
    return render(request, "password_generator/update_form.html", context)






