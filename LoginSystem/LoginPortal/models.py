from django.db import models
from django.contrib.auth.models import User


# Create your models here.

def user_directory(instance, filename):
    return '{0}/{1}/{2}'.format('profile_img', instance.user.username, filename)


class info(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    description = models.CharField(max_length=150, blank=True)
    mobile = models.IntegerField(blank=True)
    city = models.CharField(max_length=15, default='Patna')
    state = models.CharField(max_length=15, default='Bihar')
    country = models.CharField(max_length=15, default='India')
    profile_pic = models.ImageField(upload_to=user_directory, default='profile_img/default.png', blank=True)
    verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


def user_directory_path(instance, filename):
    return '{0}/{1}/{2}'.format('received', instance.profile.username, filename)


class file_handler(models.Model):
    profile = models.ForeignKey(User, on_delete=models.CASCADE)
    files = models.FileField(upload_to=user_directory_path, blank=True, default=None, null=True)
    downloaded = models.BooleanField(default=False, null=True, blank=True)
    time = models.IntegerField(default=0, null=True, blank=True)
    count = models.IntegerField(default=0, blank=True, null=True)

    def __str__(self):
        return self.profile.username


class login_attempt(models.Model):
    profile = models.OneToOneField(User, on_delete=models.CASCADE)
    count = models.IntegerField(default=0, blank=True)
    ip = models.CharField(blank=True, default='UNKNOWN', max_length=50)
    time = models.IntegerField(default=0, blank=True)

    def __str__(self):
        return self.profile.username
