from django.shortcuts import render
from .models import *
from .serializer import *
from rest_framework.views import APIView
from rest_framework.response import Response
# Create your views here.
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db.models import Q


class LoginView(TokenObtainPairView):
    serializer_class = UserTokenObtainPairSerializer

class RegistrationStudentView(APIView):

    def post(self,request):
        try:
            ser=RegistrationSer(data=request.data)
            if ser.is_valid():    
                user = ser.save()
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                return Response(data={"Status": "Success", "Msg": "Registration Successful!!!!", "data": ser.data,"tokens": {
                            "access": access_token,
                            "refresh": refresh_token
                        }}, status=status.HTTP_200_OK)
            else:
                return Response(data={"Status":"Failed","Msg":"Registration Unsuccessfull....","Errors":ser.errors},status=status.HTTP_400_BAD_REQUEST)  
        except Exception as e:
            return Response({"Status":"Failed","Error":str(e)},status=status.HTTP_400_BAD_REQUEST)
        


class GroupView(APIView):
    def get(self, request):
        user = request.user
        groups = Group.objects.filter(members=user)
        if not groups.exists():
            return Response({"message": "No groups found for this user"}, status=200)
        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = GroupSer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GroupDetailView(APIView):
    '''
    Update Group and Members
    '''
    def patch(self, request, group_id):
        try:
            group = Group.objects.get(id=group_id)
            serializer = GroupSerializer(group, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Group.DoesNotExist:
            return Response({"error": "Group object does not exist!"}, status=status.HTTP_404_NOT_FOUND)


class AddMemberToGroupView(APIView):
    '''
    Add members to an existing group
    '''
    def post(self, request, group_id):
        user = request.user
        try:
            group = Group.objects.get(id=group_id)          
            if user != group.admin: 
                return Response({"error": "You do not have permission to add members to this group"}, status=status.HTTP_403_FORBIDDEN)
            member_ids = request.data.get("members", [])
            if not member_ids:
                return Response({"error": "No members specified to add"}, status=status.HTTP_400_BAD_REQUEST)

            members_to_add = CustomUser.objects.filter(id__in=member_ids)
            for member in members_to_add:
                group.members.add(member)
            group.save()
            return Response({"success": f"Added {members_to_add.count()} members to the group"}, status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({"error": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
        except CustomUser.DoesNotExist:
            return Response({"error": "Some users not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LeaveGroupView(APIView):
    def post(self, request, group_id):
        user = request.user

        if not group_id:
            return Response({"error": "Group ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = Group.objects.get(id=group_id)
            if user not in group.members.all():
                return Response({"error": "You are not a member of this group"}, status=status.HTTP_400_BAD_REQUEST)
            group.members.remove(user)
            Notification.objects.create(
                user=user,
                message=f"You have left the group: {group.name}"
            )
            return Response({"success": "You have successfully left the group"}, status=status.HTTP_200_OK)

        except Group.DoesNotExist:
            return Response({"error": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
from django.utils.translation import activate

# from googletrans import Translator
from Crypto.Cipher import AES
import base64
import json
from Crypto.Util.Padding import unpad,pad
from google.cloud import translate_v2 as translate


class MessageView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    # Example of a 32-byte key for AES-256
    #  Example of a 32-byte key for AES-256
    SECRET_KEY = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX"  # 32 bytes

    # Ensure IV is 16 bytes (this is already correct in your code)
    IV = b"eyJhbGciOiJIUzI1"  # 16 bytes


    def get_user_language(self, request):
        """Retrieve the user's selected language from request headers or profile."""
        return request.headers.get("Accept-Language", "en")  # Default to English

    

    def encrypt_text(self, plain_text):
        """Encrypt text using AES."""
        try:
            cipher = AES.new(self.SECRET_KEY, AES.MODE_CBC, self.IV)
            padded_text = pad(plain_text.encode("utf-8"), AES.block_size)  # PKCS7 padding
            encrypted_bytes = cipher.encrypt(padded_text)
            encrypted_text = base64.b64encode(encrypted_bytes).decode("utf-8")  # Encode to Base64
            return encrypted_text
        except Exception as e:
            return f"Encryption failed: {str(e)}"

    def decrypt_text(self, encrypted_text):
        """Decrypt AES encrypted text."""
        try:
            encrypted_data = base64.b64decode(encrypted_text)  # Decode from Base64
            cipher = AES.new(self.SECRET_KEY, AES.MODE_CBC, self.IV)
            decrypted_bytes = cipher.decrypt(encrypted_data)
            decrypted_text = unpad(decrypted_bytes, AES.block_size).decode("utf-8")  # Remove padding
            return decrypted_text
        except Exception as e:
            return f"Decryption failed: {str(e)}"


         

    def translate_text(self, text, src_lang, dest_lang):
        """Translate text using Google Cloud Translate API."""
        if src_lang == dest_lang:
            return text  # No translation needed
        try:
            print(f"Source Language: {src_lang}, Destination Language: {dest_lang}")
            translate_client = translate.Client()
            print(f"Original text: {text}")

            # Translate text
            result = translate_client.translate(text, source_language=src_lang, target_language=dest_lang)
            translated_text = result['translatedText']
            print(f"Translated text: {translated_text}")

            return translated_text
        except Exception as e:
            print(f"Translation failed: {e}")
            return text # Fallback to original if translation fails

    def get(self, request):
        user = request.user
        chat_type = request.query_params.get("type")  # 'personal' or 'group'
        target_id = request.query_params.get("id")  # user ID for personal, group ID for group
        if not chat_type or not target_id:
            return Response({"error": "Chat type and target ID are required"}, status=400)

        user_language = self.get_user_language(request)  # Get user's selected language
        activate(user_language)  # Activate translation

        try:
            if chat_type == "personal":
                messages = Message.objects.filter(
                    Q(sender=user, receiver_id=target_id) | Q(sender_id=target_id, receiver=user)
                ).order_by("timestamp")
            elif chat_type == "group":
                try:
                    group = Group.objects.get(id=target_id)
                    if user not in group.members.all():
                        return Response({"error": "You are not a member of this group"}, status=403)
                except Group.DoesNotExist:
                    return Response({"error": "Group not found"}, status=404)
                messages = Message.objects.filter(group=group)
            else:
                return Response({"error": "Invalid chat type"}, status=400)

            if not messages.exists():
                return Response({"message": "No messages found"}, status=200)

            # Serialize messages
            serializer = MessageSerializer(messages, many=True)
            data = serializer.data
 
            # Process messages: Decrypt -> Translate -> Encrypt
            # print(data)
            for message in data:
                decrypted_text = self.decrypt_text(message["content"])  # Step 1: Decrypt
                print("decrypted",decrypted_text)
                translated_text = self.translate_text(decrypted_text, "auto", user_language)  # Step 2: Translate
                print("translated",translated_text)
                encrypted_text = self.encrypt_text(translated_text)  # Step 3: Encrypt
                message["content"] = encrypted_text  # Step 4: Replace with encrypted translated text

            return Response(data)
        except Exception as e: 
            return Response({"error": str(e)}, status=500)  

    def post(self, request):
        try:
            data = request.data
            sender = request.user
            print(sender)
            message = data.get('message')
            receiver_id = data.get('receiver')  # For one-to-one chat
            group_id = data.get('group')  # For group chat
            image = request.FILES.get('image')  # Get image from request

            if not message and not image:
                return Response({"error": "Message content or image is required"}, status=400)

            if receiver_id:  # One-to-one chat
                try:
                    receiver = CustomUser.objects.get(id=receiver_id)
                    print(receiver_id)   
                    print(image)
                    msg = Message.objects.create(
                        sender=sender,
                        receiver=receiver,
                        content=message,
                        image=image,
                        # is_image=bool(image)  # Set is_image to True if image is uploaded
                    )
                    Notification.objects.create(
                        user=receiver,
                        message=f"You have a new message from {sender.name}: {message or 'Image'}"
                    )
                    return Response({"success": "Message sent successfully", "message_id": msg.id}, status=201)
                except CustomUser.DoesNotExist:
                    return Response({"error": "Receiver not found"}, status=404)

            elif group_id:  # Group chat
                try:
                    group = Group.objects.get(id=group_id)
                    if sender not in group.members.all():  # Assuming `members` is a ManyToManyField
                        return Response({"error": "You are not a member of this group"}, status=403)
                    
                    msg = Message.objects.create(
                        sender=sender,
                        group=group,
                        content=message,
                        image=image,
                        is_image=bool(image)  # Set is_image based on image presence
                    )
                    
                    for member in group.members.all():
                        if member != sender:
                            Notification.objects.create(
                                user=member,
                                message=f"New message in group {group.name}: {message or 'Image'}"
                            )
                    
                    return Response({"success": "Message sent to group successfully", "message_id": msg.id}, status=201)
                except Group.DoesNotExist:
                    return Response({"error": "Group not found"}, status=404)
            
            else:
                return Response({"error": "Receiver or group ID is required"}, status=400)

        except Exception as e:
            return Response({"error": str(e)}, status=500)



class UsersView(APIView):
    def get(self,request):
        users = CustomUser.objects.all()
        serializer = RegistrationSer(users,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    

class GetNotificationsView(APIView):
    def get(self, request):
        user = request.user 
        notifications = Notification.objects.filter(user=user).order_by('-created_at')
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)


class MarkAsReadView(APIView):
    def patch(self, request, notification_id):
        try:
            notification = Notification.objects.get(id=notification_id, user=request.user)
            notification.read = True
            notification.save()
            return Response({"success": "Notification marked as read"}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)

from django.http import JsonResponse
from googletrans import Translator
def translate_text(request):
    if request.method == "POST":
        text = request.POST.get("text")
        source_lang = request.POST.get("source_lang")
        target_lang = request.POST.get("target_lang")
        
        if not text or not source_lang or not target_lang:
            return JsonResponse({"error": "Missing parameters. Please provide text, source_lang, and target_lang."}, status=400)
        
        try:
            translator = Translator()
            translated = translator.translate(text, src=source_lang, dest=target_lang)
            return JsonResponse({"translated_text": translated.text}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method. Use POST."}, status=405)

from django.utils.timezone import make_aware
from datetime import datetime
import pytz


class ScheduleMessageView(APIView):
    def post(self, request):
        sender_id = request.user.id
        receiver_id = request.data.get('receiver_id')
        group_id = request.data.get('group_id')
        content = request.data.get('content', '')
        image = request.FILES.get('image')
        send_time = request.data.get('send_time')

        if send_time:
            # Parse the string to a naive datetime object
            naive_datetime = datetime.strptime(send_time, '%Y-%m-%d %H:%M:%S')

            # Make it timezone-aware in IST
            ist_timezone = pytz.timezone('Asia/Kolkata')
            send_time = make_aware(naive_datetime, timezone=ist_timezone)

        scheduled_message = MessageScheduler.objects.create(
            sender_id=sender_id,
            receiver_id=receiver_id,
            group_id=group_id,
            content=content,
            image=image,
            scheduled_time=send_time
        )  
        return Response({"message": "Message scheduled successfully", "scheduled_message_id": scheduled_message.id})