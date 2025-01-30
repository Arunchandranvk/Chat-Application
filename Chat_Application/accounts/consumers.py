import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import User
from .models import Message, Group

class ChatConsumer(AsyncWebsocketConsumer):
    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message = data.get('message')
            sender_username = data.get('sender')
            receiver_username = data.get('receiver', None)  
            group_id = data.get('group', None)  
            if not message or not sender_username:
                await self.send(json.dumps({"error": "Message and sender are required"}))
                return
            sender = User.objects.get(username=sender_username)
            if receiver_username: 
                receiver = User.objects.get(username=receiver_username)
                Message.objects.create(sender=sender, receiver=receiver, content=message)
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message,
                        'sender': sender_username,
                        'receiver': receiver_username,
                    }
                )
            elif group_id:  
                group = Group.objects.get(id=group_id)
                Message.objects.create(sender=sender, group=group, content=message)
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message,
                        'sender': sender_username,
                        'group': group.name,
                    }
                )
            else:
                await self.send(json.dumps({"error": "Receiver or group ID is required"}))
        except User.DoesNotExist:
            await self.send(json.dumps({"error": "User not found"}))
        except Group.DoesNotExist:
            await self.send(json.dumps({"error": "Group not found"}))
        except Exception as e:
            await self.send(json.dumps({"error": str(e)}))

    async def chat_message(self, event):
        message = event['message']
        sender = event['sender']
        receiver = event.get('receiver', None)
        group = event.get('group', None)

        await self.send(json.dumps({
            'message': message,
            'sender': sender,
            'receiver': receiver,
            'group': group,
        }))

