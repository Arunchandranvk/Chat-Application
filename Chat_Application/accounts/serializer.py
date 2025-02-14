from rest_framework import serializers
from .models import *



from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class UserTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['id']=user.id
        token['name'] = user.name
        token['phone'] = user.phone
        token['email'] = user.email

        return token
    
    def validate(self, attrs):
        data = super().validate(attrs)
        user=self.user
        data['id']=user.id
        data['name'] = user.name
        data['phone'] = user.phone
        data['email'] = user.email

        return data


class RegistrationSer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    id=serializers.ReadOnlyField()
    class Meta:
        model=CustomUser
        fields=['id','name','phone','email','password']
        
    def create(self,validated_data):
        return CustomUser.objects.create_user(**validated_data)

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = '__all__'



class GroupSerializer(serializers.ModelSerializer):
    members = serializers.SerializerMethodField()

    class Meta:
        model = Group
        fields = '__all__'

    def get_members(self, obj):
        return [{"id": member.id, "name": member.name} for member in obj.members.all()]

class GroupSer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fields = '__all__'

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'user', 'message', 'read', 'created_at']