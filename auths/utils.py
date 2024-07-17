# 카카오 인증 코드를 사용하여 액세스 토큰을 교환하고 사용자 정보를 가져오는 유틸리티 함수 정의

import requests
import os

class KakaoAccessTokenException(Exception):
    pass

# 로그인 페이지를 통해 인증을 마치고 access_code를 받아, 카카오 API를 통해 access token을 교환
# access token : 사용자가 카카오 API에 접근 할 수 있는 권한을 나타냄

def exchange_kakao_access_token(access_code):
    response = requests.post(
        'https://kauth.kakao.com/oauth/token',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        },
        data={
            'grant_type': 'authorization_code',
            'client_id': os.environ.get('KAKAO_REST_API_KEY'),
            'client_secret': os.environ.get('CLIENT_SECRET'),
            'redirect_uri': os.environ.get('KAKAO_REDIRECT_URI'),
            'code': access_code,
        },
    )
    if response.status_code >= 300:
        raise KakaoAccessTokenException(response.json())
    return response.json()

def get_kakao_user_info(access_token):
    response = requests.get(
        'https://kapi.kakao.com/v2/user/me',
        headers={
            'Authorization': f'Bearer {access_token}',
        },
    )
    if response.status_code >= 300:
        raise KakaoAccessTokenException(response.json())
    return response.json()