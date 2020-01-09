from django.db import models
from django.contrib.auth.models import User


# Create your models here.

def user_directory(instance, filename):
    return '{0}/{1}/{2}'.format('profile_img', instance.user.username, filename)


class info(models.Model):
    all_branches = (
        ('1', 'IT'),
        ('2', 'Comp'),
        ('3', 'Chemical'),
        ('4', 'Mechanical'),
        ('5', 'Civil'),
        ('6', 'EnTc'),
        ('7', 'ETX')
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    description = models.CharField(max_length=150, blank=True)
    mobile = models.IntegerField(blank=True)
    city = models.CharField(max_length=15, default='Patna')
    state = models.CharField(max_length=15, default='Bihar')
    country = models.CharField(max_length=15, default='India')
    branch = models.CharField(max_length=20, choices=all_branches)
    profile_pic = models.ImageField(upload_to=user_directory, default='profile_img/default.png', blank=True)
    verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


def user_directory_path(instance, filename):
    return '{0}/{1}/{2}/{3}'.format('received', instance.profile.username, instance.sent_by, filename)


class file_handler(models.Model):
    profile = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    downloaded = models.BooleanField(default=False, null=True, blank=True)
    time = models.IntegerField(default=0, null=True, blank=True)
    count = models.IntegerField(default=0, blank=True, null=True)
    sent_by = models.CharField(blank=True, null=True, max_length=150)
    files = models.FileField(upload_to=user_directory_path, blank=True, default=None, null=True)

    def __str__(self):
        return self.profile.username


class login_attempt(models.Model):
    profile = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    count = models.IntegerField(default=0, blank=True)
    ip = models.CharField(blank=True, default='UNKNOWN', max_length=50)
    time = models.IntegerField(default=0, blank=True)

    def __str__(self):
        return self.profile.username


class friends(models.Model):
    profile = models.ForeignKey(info, on_delete=models.CASCADE, related_name='friend_request', null=True)
    friend = models.ForeignKey(info, on_delete=models.CASCADE, null=True)
    accept = models.BooleanField(default=False, null=True)

    class Meta:
        unique_together = ['profile', 'friend']

    def __str__(self):
        return self.friend.user.username
