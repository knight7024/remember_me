from django.shortcuts import render
from django.conf import settings
from django.http import Http404
import jwt, datetime, json, time

# Create your views here.

class Generate_Token: # 토큰 생성
    nowDateTime = datetime.datetime.now() # 현재 DateTime
    unixTimeStamp = int(time.mktime(nowDateTime.timetuple())) # DateTime to Unix TimeStamp
    # JWT - header
    myHeader = {
        'alg': 'HS256',
        'typ': 'JWT',
    }
    # HS256 비밀키
    config_secret_common = json.loads(open(settings.CONFIG_SECRET_COMMON_FILE).read())
    secret = config_secret_common['REMEMBER_ME']['SECRET']

    def refresh_token(self, username): # GENERATE REFRESH TOKEN
        # JWT - payload
        myPayload = {
            'username': username, # 유저 아이디
            'exp': self.unixTimeStamp + (60 * 60 * 24 * 60), # 만료 기간 2달
            'iat': self.unixTimeStamp # 발급 일자
        }
        encodedJWT = jwt.encode(myPayload, self.secret, algorithm='HS256', headers=self.myHeader)
        return encodedJWT

    def access_token(self, username): # GENERATE ACCESS TOKEN
        # JWT - payload
        myPayload = {
            'username': username, # 유저 네임
            'exp': self.unixTimeStamp + (60 * 60 * 24 * 7), # 만료 기간 1주
            'iat': self.unixTimeStamp # 발급 일자
        }
        encodedJWT = jwt.encode(myPayload, self.secret, algorithm='HS256', headers=self.myHeader)
        return encodedJWT

    def decode_token(self, encodedJWT, verify=True): # DECODE JWT TOKEN
        return jwt.decode(encodedJWT, self.secret, algorithms='HS256', verify=verify)

    def valid_token(self, myRemember, username, myAccessToken=None): # 토큰 갱신
        try: # REFRESH TOKEN이
            decoded_payload = self.decode_token(myRemember.token)

        except jwt.exceptions.DecodeError: # 변조된 토큰이라면
            # 이런 경우가 있는가?
            raise Http404('ACCESS DENIED!') # 404 Error

        except jwt.exceptions.ExpiredSignatureError: # 만료된 토큰이라면
            # 갱신
            myRemember.token = self.refresh_token(username).decode()
            myRemember.save()
            # print('****************** REFRESH TOKEN 갱신 완료 ******************')

        finally:
            # REFRESH TOKEN의 검사가 끝나면
            if not myAccessToken: # ACCESS TOKEN이 없다면
                myAccessToken = self.access_token(username).decode()
                # print('****************** ACCESS TOKEN 발급 완료 ******************')

            else: # 있다면
                print("passed")
                try: # ACCESS TOKEN이
                    decoded_payload = self.decode_token(myAccessToken)
                
                except jwt.exceptions.ExpiredSignatureError: # 만료된 토큰이라면
                    # 갱신
                    myAccessToken = self.access_token(username).decode()
                    # print('****************** ACCESS TOKEN 갱신 완료 ******************')

                except jwt.exceptions.DecodeError: # 변조된 토큰이라면
                    raise Http404('ACCESS DENIED!') # 404 Error
            
            return myAccessToken # 반환