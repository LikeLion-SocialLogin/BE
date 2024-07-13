from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class Member(AbstractUser):   # 장고 기본 user와 호환되고, 우리 프로젝트에 맞는 새로운 유저 생성
    email = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    def __str__(self):
        return self.name