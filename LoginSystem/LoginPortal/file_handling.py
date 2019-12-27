import os
import time
from zipfile import ZipFile

from .models import file_handler


def get_zip_file(filenames=[]):
    if len(filenames) > 0:
        dir_split = os.path.split(filenames[0])
        os.chdir(
            os.path.join(os.getcwd(), os.path.join('media', os.path.join('received', dir_split[len(dir_split) - 2]))))
        path = os.path.join(os.path.dirname(filenames[0]), 'Download.zip')

        if os.path.exists(path):
            os.remove(path)

        with ZipFile('Download.zip', 'w', ) as zf:
            for filename in filenames:
                split = os.path.split(filename)
                zf.write(split[len(split) - 1])
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
