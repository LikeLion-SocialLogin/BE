from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Member
from .serializers import MemberSerializer
from .utils import exchange_kakao_access_token, get_kakao_user_info, KakaoAccessTokenException

# 로그인
@api_view(['POST'])
def kakao_login(request):
    access_code = request.data.get('code')    # 클라이언트로부터 전달된 요청 데이터에서 'code'를 가져옴. 이 code는 카카오 OAuth2 인증 후 얻는 code
    if not access_code:
        return Response({'message': '코드 에러'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token_response = exchange_kakao_access_token(access_code)   # 카카오 OAuth2 액세스 코드를 사용하여 카카오 access token 교환
        access_token = token_response['access_token']
        kakao_user_info = get_kakao_user_info(access_token)    # 교환된 액세스 토큰을 사용하여 카카오 사용자 정보를 가져옴.
        
        kakao_id = kakao_user_info['id']
        email = kakao_user_info.get('kakao_account', {}).get('email')
        name = kakao_user_info.get('properties', {}).get('nickname')

        if not email:
            return Response({'message': '존재하지 않는 유저입니다.'}, status=status.HTTP_404_NOT_FOUND)

        # 회원가입 되어 있는 사용자 -> 로그인
        try:
            member = Member.objects.get(kakao_id=kakao_id)
        except Member.DoesNotExist:
            return Response({'message': '존재하지 않는 유저입니다.'}, status=status.HTTP_404_NOT_FOUND)
        
        # refresh 토큰 - 사용자를 인증하고, 토큰의 유효기간이 만료되었을 때 새로운 access 토큰을 발급받을 수 있는 역할을 함
        refresh = RefreshToken.for_user(member)   # 해당 user를 기반으로 JWT의 refresh 토큰을 생성하고 관리
        member_serializer = MemberSerializer(member)  # Member 모델을 JSON 형태로 변환
        
        return Response({
            'refresh': str(refresh),    # refresh 토큰
            'access': str(refresh.access_token),  # access 토큰
            'member': member_serializer.data,  # 사용자 정보가 포함된 JSON 데이터
        })            

    except KakaoAccessTokenException as e:
        return Response({'error': 'Failed to obtain access token', 'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)

# 회원가입
@api_view(['POST'])
def kakao_signup(request):
    access_code = request.data.get('code')
    if not access_code:
        return Response({'message': '코드 에러'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token_response = exchange_kakao_access_token(access_code)
        access_token = token_response['access_token']
        kakao_user_info = get_kakao_user_info(access_token)
        
        kakao_id = kakao_user_info['id']
        email = kakao_user_info.get('kakao_account', {}).get('email')
        name = kakao_user_info.get('properties', {}).get('nickname')

        # 사용자가 이미 존재하는지 확인
        if Member.objects.filter(kakao_id=kakao_id).exists():
            return Response({'message': '이미 존재하는 회원입니다.'}, status=status.HTTP_400_BAD_REQUEST)

        # 새로운 사용자 생성
        member = Member.objects.create(
            kakao_id=kakao_id,
            email=email,
            name=name,
        )
        member.set_unusable_password()  # 소셜 로그인 사용자는 비밀번호를 직접 설정하지 않음
        member.save()

        # JWT 토큰 발급
        refresh = RefreshToken.for_user(member)
        member_serializer = MemberSerializer(member)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'member': member_serializer.data,
        })

    except KakaoAccessTokenException as e:
        return Response({'error': 'Failed to obtain access token', 'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)