# 실행 명령어 


가상환경 생성 및  on
```
python -m venv venv
venv/Scripts/activate 
```

project 클론 및 실행 
```
git clone https://github.com/LikeLion-SocialLogin/BE.git
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py runserver 
python manage.py createsuperuser
```