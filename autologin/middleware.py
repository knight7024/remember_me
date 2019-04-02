from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import auth
from django.http import Http404
from .views import Generate_Token
from accounts.models import Remember_Me
import jwt


class AutoLoginMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        is_deleted_user = False
        # 로그인된 상태가 아니라면
        if not request.user.is_authenticated:
            # 쿠키에서 ACCESS TOKEN을 불러옴
            access_token = request.COOKIES.get('access_token', None)
            if access_token:
                try: # ACCESS TOKEN이
                    manage_token = Generate_Token()
                    decoded_payload = manage_token.decode_token(access_token)

                except jwt.exceptions.DecodeError: # 변조된 토큰이라면
                    raise Http404('ACCESS DENIED!') # 404 Error

                except jwt.exceptions.ExpiredSignatureError: # 만료된 토큰이라면
                    unverified_decoded_payload = manage_token.decode_token(access_token, False)
                    username = unverified_decoded_payload['username']
                    # username = decoded_payload['username']
                    userid = User.objects.get(username=username).id # USER ID
                    remember = Remember_Me.objects.get(userid=userid)
                    access_token = manage_token.valid_token(remember, username, access_token)

                finally:
                    decoded_payload = manage_token.decode_token(access_token)
                    username = decoded_payload['username'] # 최종 유저네임 가져와서

                    try:
                        user = User.objects.get(username=username)

                    except User.DoesNotExist:
                        is_deleted_user = True

                    else:
                        user.backend = 'django.contrib.auth.backends.ModelBackend'
                        # 로그인
                        if user is not None:
                            request.user = user
                            auth.login(request, user)
                
        response = self.get_response(request)

        if is_deleted_user:
            response.delete_cookie('access_token')

        # Code to be executed for each request/response after
        # the view is called.
                    
        return response