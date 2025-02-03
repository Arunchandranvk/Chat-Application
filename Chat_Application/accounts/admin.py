from django.contrib import admin
from .models import *
# Register your models here.


admin.site.register(CustomUser)
admin.site.register(Group)
admin.site.register(Message)
admin.site.register(Notification)