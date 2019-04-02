from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.urls import reverse
from django.contrib import auth
from django.views import View
from .models import Remember_Me
from autologin.views import Generate_Token
import jwt

# Create your views here.

# 로그인
class Signin(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'signin.html')
    
    def post(self, request, *args, **kwargs):
        response = redirect('index')
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = auth.authenticate(request, username=username, password=password)
        if user is not None:
            remember_login = request.POST.get('loginchk', 'off')
            auth.login(request, user)
            # 만약 항상 로그인을 체크한 후 로그인 했다면
            if remember_login == 'on':
                access_token = request.session.get('access_token', None) # ACCESS TOKEN
                userid = User.objects.get(username=username).id # USER ID

                try: # 로그인한 유저가
                    remember = Remember_Me.objects.get(userid=userid)

                except Remember_Me.DoesNotExist: # 존재하지 않으면
                    # GENERATE TOKEN
                    manage_token = Generate_Token()
                    access_token = manage_token.access_token(username).decode()
                    refreshToken = manage_token.refresh_token(username).decode()
                    # SAVE TO MODEL
                    remember = Remember_Me()
                    remember.userid = userid
                    remember.token = refreshToken
                    remember.save()
                    # 세션에 ACCESS TOKEN 저장
                    response.set_cookie('access_token', access_token, max_age=99999999, httponly=True)
                
                else: # 존재하면
                    manage_token = Generate_Token()
                    access_token = manage_token.valid_token(remember, username)
                    # 세션에 ACCESS TOKEN 저장
                    response.set_cookie('access_token', access_token, max_age=999999999, httponly=True)
            return response
        else:
            return render(request, 'signin.html', { 'error': 'Failed To Sign-In!' })

# 회원가입
class Signup(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'signup.html')
    
    def post(self, request, *args, **kwargs):
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirmation', '')
        if password == password_confirm:
            try:
                user = User.objects.get(username=username)
                return render(request, 'signup.html', { 'error': 'Duplicated Username Existed!' })
            except User.DoesNotExist:
                user = User.objects.create_user(username=username, password=password)
                auth.login(request, user)
                return redirect('index')

class Signout(View):
    def get(self, request, *args, **kwargs):
        response = redirect('index')
        response.delete_cookie('access_token')
        auth.logout(request)
        return response