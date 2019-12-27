from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('register', views.register, name='register'),
    path('logout', views.user_logout, name='user_logout_page'),
    path('login', views.user_login, name='user_login_page'),
    path('profile', views.logged_in, name='user_success_page'),
    path('delete', views.user_delete, name='user_success_delete'),
    path('recovery', views.recoverpassword, name='user_change_password'),
    path('download', views.call_download, name='user_request_download'),
    path('delete_files', views.delete_download, name='user_delete_download'),
]
