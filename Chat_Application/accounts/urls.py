from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginView.as_view(),name='log'),
    path('registration/',RegistrationStudentView.as_view(),name='reg_stu'),
    path('groups/', GroupView.as_view(), name='groups'),
    path('groups/<int:group_id>/', GroupDetailView.as_view(), name='groups-detail'),
    path('messages/', MessageView.as_view(), name='messages'),
    path('leave-group/<int:group_id>/', LeaveGroupView.as_view(), name='leave'),
    path('all-users/', UsersView.as_view(), name='alluser'),
    path('notifications/', GetNotificationsView.as_view(), name='get_notifications'),
    path('notifications/mark_as_read/<int:notification_id>/', MarkAsReadView.as_view(), name='mark_as_read'),
    path("translate/", translate_text, name="translate_text"),

]
