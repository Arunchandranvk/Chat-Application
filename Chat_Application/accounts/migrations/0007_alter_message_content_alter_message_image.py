# Generated by Django 5.1.4 on 2025-02-04 10:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_message_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='content',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='message',
            name='image',
            field=models.FileField(blank=True, null=True, upload_to='messages_Image'),
        ),
    ]
