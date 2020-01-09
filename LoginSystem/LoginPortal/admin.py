from django.contrib import admin
from LoginPortal.models import info, file_handler, login_attempt, friends


# Register your models here.

admin.site.register(info)
admin.site.register(file_handler)
admin.site.register(login_attempt)
admin.site.register(friends)
