from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from datetime import timedelta
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError

# Create your models here.


def validate_phone(value):
    if len(str(value)) != 10:
        raise ValidationError("Phone number must be exactly 10 digits.")
    if not str(value).isdigit():
        raise ValidationError("Phone number must contain only digits.")


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None , **extra_fields):
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone=models.BigIntegerField(unique=True,validators=[validate_phone])
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name','phone']

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

    def _str_(self):
        return self.email


class Group(models.Model):
    name = models.CharField(max_length=100)
    members = models.ManyToManyField(CustomUser, related_name='groups_members')
    admin = models.ForeignKey(CustomUser,on_delete=models.CASCADE,related_name="group_created_user",null=True)

    def __str__(self):
        return self.name

class Message(models.Model):
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sent_messages',null=True)
    receiver = models.ForeignKey(CustomUser, null=True, blank=True, related_name='received_messages', on_delete=models.CASCADE)
    group = models.ForeignKey(Group, null=True, blank=True, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.group:
            return f"Group: {self.group.name} - {self.sender.name}: {self.content}"
        else:
            return f"{self.sender.name} to {self.receiver.name}: {self.content}"


class Notification(models.Model):
    user = models.ForeignKey(CustomUser, related_name='notifications', on_delete=models.CASCADE)
    message = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.name} - {self.message[:20]}"