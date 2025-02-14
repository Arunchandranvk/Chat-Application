from django.apps import AppConfig
from django.db import connections
from django.core.management import call_command
from django.db.utils import OperationalError
import threading
import time
from django.utils import timezone
from datetime import timedelta

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        # Delay the execution until the database is ready
        threading.Thread(target=start_message_scheduler, daemon=True).start()


def wait_for_db():
    """Wait until the database is ready before running the background thread."""
    while True:
        try:
            connections["default"].cursor()  # Try connecting to the DB
            return
        except OperationalError:
            print("Database not ready, waiting...")
            time.sleep(50)



def start_message_scheduler():
    """Wait for the database and then start processing scheduled messages."""

    from .models import MessageScheduler, Message
    wait_for_db()  # Ensure the database is ready before running queries

    while True:
        now = timezone.now() 
       
        print(f"Checking scheduled messages at {now}")  # Debugging output

        messages = MessageScheduler.objects.filter(scheduled_time__lte=now)
        for scheduled_message in messages:
            sender = scheduled_message.sender
            receiver = scheduled_message.receiver
            group = scheduled_message.group
            content = scheduled_message.content
            image_path = scheduled_message.image.path if scheduled_message.image else None

            # Create and send the message
            Message.objects.create(
                sender=sender,
                receiver=receiver,
                group=group,
                content=content,
                image=image_path,
            )

            # Remove from the schedule after sending
            # scheduled_message.is_sent = True
            scheduled_message.delete()

        time.sleep(60)  # Check every 10 seconds