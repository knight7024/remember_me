from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import auth
from django.urls import reverse
from django.views import View

# Create your views here.

class Signin(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'signin.html')
    
    def post(self, request, *args, **kwargs):
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(request, username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('index')
        else:
            return render(request, 'signin.html', { 'error': 'Failed To Sign-In!' })

class Signup(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'signup.html')
    
    def post(self, request, *args, **kwargs):
        username = request.POST['username']
        password = request.POST['password']
        password_confirm = request.POST['password_confirmation']
        if password == password_confirm:
            try:
                user = User.objects.get(username=username)
                return render(request, 'signup.html', { 'error': 'Duplicated Username Existed!' })
            except User.DoesNotExist:
                user = User.objects.create_user(username=username, password=password)
                auth.login(request, user)
                return redirect('index')

class Signout(View):
    def post(self, request, *args, **kwargs):
        auth.logout(request)
        return redirect('index')