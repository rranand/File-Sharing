import os
import time
from zipfile import ZipFile

from LoginPortal.models import file_handler
from django import forms


def get_zip_file(filenames=[]):
    if len(filenames) > 0:
        dir_split = os.path.split(filenames[0])
        os.chdir(os.path.split(dir_split[0])[0])
        path = os.path.join(os.getcwd(), 'Download.zip')

        if os.path.exists(path):
            os.remove(path)

        with ZipFile('Download.zip', 'w', ) as zf:
            for filename in filenames:
                zf.write(os.path.join(os.path.split(os.path.split(filename)[0])[1], os.path.split(filename)[1]))
        return path
    return None


def cleanup():
    try:
        files = file_handler.objects.all()
    except file_handler.DoesNotExist:
        return

    for file in files:
        if int(int(time.time() - int(file.time))) > 259200:
            os.remove(file.files.path)
            file.delete()


def attribute_manager(f4, f5):
    f4.fields['first_name'].widget = forms.TextInput(attrs={'readonly': True})
    f4.fields['last_name'].widget = forms.TextInput(attrs={'readonly': True})
    f4.fields['email'].widget = forms.TextInput(attrs={'readonly': True})
    f4.fields['username'].widget = forms.HiddenInput()
    f4.fields['password'].widget = forms.HiddenInput()
    f4.fields['v_password'].widget = forms.HiddenInput()
    f5.fields['mobile'].widget = forms.TextInput(attrs={'readonly': True})

