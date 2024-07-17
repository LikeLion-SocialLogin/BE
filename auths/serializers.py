from rest_framework import serializers
from .models import Member

class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ['id', 'name', 'email']
        extra_kwargs = {
            'email': {'read_only': True}  # 'id' 필드를 읽기 전용으로 설정
        }

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        # instance.email = validated_data.get('email', instance.email)
        instance.save()
        return instance