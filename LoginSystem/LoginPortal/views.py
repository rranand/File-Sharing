import os
import re
import time

from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.encoding import smart_str
from ipware import get_client_ip

from LoginPortal.mail import generate_otp, recover_mail, generate_password
from .file_handling import get_zip_file, cleanup
from .forms import basic_detail, more_detail, login_form, change_password, search, otp_authentication, \
    files_handler, recover_password
from .models import info, file_handler, login_attempt

otp = None


# Create your views here.

def home(request):
    cleanup()
    try:
        info.objects.get(user=request.user)
    except TypeError:
        return render(request, 'home.html')
    except info.DoesNotExist:
        request.session.flush()
        return render(request, 'home.html')
    return render(request, 'home.html', context={'user': request.user})


def register(request):
    cleanup()
    f1 = basic_detail()
    f2 = more_detail()

    if request.method == 'POST':
        f1 = basic_detail(request.POST)
        f2 = more_detail(request.POST)

        if f1.is_valid() and f2.is_valid():

            basic_data = f1.save()
            basic_data.set_password(basic_data.password)
            basic_data.save()

            more_data = f2.save(commit=False)
            more_data.user = basic_data

            if 'profile_pic' in request.FILES:
                more_data.profile_pic = request.FILES['profile_pic']

            more_data.save()

            return render(request, 'home.html', context={'registered': True})

    return render(request, 'register.html', {'form1': f1, 'form2': f2, 'user': request.user})


def user_login(request):
    cleanup()
    f1 = login_form()

    if request.method == 'POST':
        f1 = login_form(data=request.POST)

        if f1.is_valid():
            username = f1.cleaned_data['username']
            password = f1.cleaned_data['password']

            if bool(re.search('^[\w|\.|+|-]{1,150}$', str(username))):
                if not bool(re.search('[=:^%\'\"]{1,}', str(password))):
                    user = authenticate(request, username=username, password=password)

                    try:
                        profile_check = info.objects.get(user__username=username)
                        login_try, created = login_attempt.objects.get_or_create(profile=profile_check.user)
                        dont = False
                    except info.DoesNotExist:
                        dont = True

                    if user:
                        if (not dont) and int(time.time()) - int(
                                login_try.time) <= 300 and login_try.count == 5:
                            message = 'You are still blocked!!! ' + str(
                                300 - int(int(time.time()) - int(login_try.time))) + ' seconds left!!! '
                            return render(request, 'login.html', context={'error': message, 'login_form': f1})
                        login_try.time = 0
                        login_try.count = 0
                        login_try.ip, routable = get_client_ip(request)
                        login_try.save(update_fields=['count', 'time', 'ip'])
                        login(request, user)
                        return HttpResponseRedirect(reverse('user_success_page'))

                    elif user is None:
                        if not dont:
                            if login_try.count < 5:
                                login_try.count += 1
                                message = 'Authentication failed....Verify username and password ' + str(
                                    5 - int(login_try.count)) + 'attempt left!!!'
                            elif login_try.count == 5:
                                message = 'You have been blocked for 5 minutes. Please Login after 5 minutes'
                                login_try.time = int(time.time())
                                login_try.ip, routable = get_client_ip(request)
                            login_try.save(update_fields=['count', 'time', 'ip'])
                        else:
                            message = 'Authentication failed....Verify username and password'
                        return render(request, 'login.html', content_type=dict,
                                      context={'error': message,
                                               'login_form': f1})

                else:
                    return render(request, 'login.html', content_type=dict,
                                  context={'login_form': f1, 'error': 'Password is not valid'})

            else:
                return render(request, 'login.html', content_type=dict, context={'login_form': f1, 'error': 'Username '
                                                                                                            'is not '
                                                                                                            'valid'})

    return render(request, 'login.html', context={'login_form': f1})


def logged_in(request):
    cleanup()
    global otp
    f1 = change_password()
    f2 = search()
    f3 = otp_authentication()
    f4 = files_handler()

    try:
        profile = info.objects.get(user=request.user)
    except info.DoesNotExist:
        return render(request, 'profile.html', context={'error': 'Can\'t retrieve data from database'})
    except TypeError:
        return HttpResponseRedirect(reverse('home'))

    if not profile.verified and len(str(otp)) != 6:
        otp = generate_otp(email=str(profile.user.email))

    if request.method == 'POST':
        f1 = change_password(data=request.POST)
        f2 = search(data=request.POST)
        f3 = otp_authentication(data=request.POST)
        f4 = files_handler(data=request.POST)

        if f1.is_valid():
            cpass = f1.cleaned_data['current']
            npass = f1.cleaned_data['new_password']
            vpass = f1.cleaned_data['v_new_password']

            for i in [cpass, npass, vpass]:
                if bool(re.search('[=:^%\'\"]{1,}', str(i))):
                    return render(request, 'profile.html', context={'error': 'Password is not valid'})
            if request.user.check_password(str(cpass)):
                if npass == vpass:
                    request.user.set_password(npass)
                    request.user.save()
                    request.session.flush()
                    return render(request, 'home.html', context={
                        'message': 'Your password has been changed successfully. Please login again'})

        if f2.is_valid():
            search_profile = f2.cleaned_data['search_profile']

            if bool(re.search('[\d]{4,10}', str(search_profile))) or bool(
                    re.search('[@]{1}', str(search_profile))) or bool(re.search('^[a-zA-Z]{3,}$', str(search_profile))):

                all_profiles = info.objects.filter(mobile__iregex=str(search_profile)) or info.objects.filter(
                    user__email__iregex=str(search_profile)) or info.objects.filter(
                    user__first_name__exact=str(search_profile))

                if not all_profiles.exists():
                    return render(request, 'profile.html', content_type=dict,
                                  context={'profile': profile, 'change_password': f1, 'search': f2,
                                           'send_or_receive': f4,
                                           'search_message': str(str(search_profile) + ' not found')})

                else:
                    return render(request, 'profile.html', content_type=dict,
                                  context={'profile': profile, 'change_password': f1, 'search': f2,
                                           'send_or_receive': f4,
                                           'result': all_profiles})

            else:
                return render(request, 'profile.html', content_type=dict,
                              context={'profile': profile, 'change_password': f1, 'search': f2,
                                       'send_or_receive': f4,
                                       'search_message': 'Provide Correct Details'})
        if not profile.verified:
            if f3.is_valid():
                key = f3.cleaned_data['key']
                if len(str(key)) == 6 and str(otp) == str(key):
                    profile.verified = True
                    profile.save(update_fields=['verified'])
                    otp = None
                    return render(request, 'profile.html', content_type=dict,
                                  context={'profile': profile, 'change_password': f1, 'search': f2,
                                           'send_or_receive': f4,
                                           'verification': 'Your account has been verified successfully'})
                else:
                    return render(request, 'profile.html', content_type=dict,
                                  context={'profile': profile, 'otp_verify': f3,
                                           'message': 'OTP is not valid...please verify your otp'})

        if f4.is_valid():
            if 'files' in request.FILES:
                for file in request.FILES.getlist('files'):
                    handler = file_handler(profile=request.user, files=file, time=int(time.time()))
                    handler.save()
            return HttpResponseRedirect(reverse('user_success_page'))

    return render(request, 'profile.html', content_type=dict,
                  context={'profile': profile, 'change_password': f1, 'search': f2, 'otp_verify': f3,
                           'send_or_receive': f4})


@login_required(login_url='home')
def user_logout(request):
    cleanup()
    logout(request)
    return render(request, 'home.html', context={'message': 'You logged out successfully.'})


@login_required(login_url='home')
def user_delete(request):
    cleanup()
    try:
        user = info.objects.get(user=request.user)
    except info.DoesNotExist:
        request.session.flush()
        return render(request, 'home.html', context={'message': 'Technical Error, login again'})
    user.delete()
    request.user.delete()
    user_logout(request)
    request.session.flush()
    return render(request, 'home.html', context={'message': 'Your account has been deleted successfully'})


def recoverpassword(request):
    cleanup()
    f1 = recover_password()

    if request.method == 'POST':
        f1 = recover_password(data=request.POST)

        if f1.is_valid():
            username = f1.cleaned_data['username']
            email = f1.cleaned_data['email']
            mobile = f1.cleaned_data['mobile']

            if not bool(re.search('^[\w|\.|+|-]{1,150}$', str(username))):
                return render(request, 'recovery.html',
                              context={'recovery': f1, 'message': 'Provided username is wrong'})
            elif not bool(re.search('[\d]{10}', str(mobile))):
                return render(request, 'recovery.html',
                              context={'recovery': f1, 'message': 'Provided mobile number is wrong'})

            try:
                to_be_recovered = info.objects.get(user__username=username)
            except info.DoesNotExist:
                return render(request, 'recovery.html',
                              context={'recovery': f1, 'message': 'Provided details are wrong'})

            if str(to_be_recovered.mobile) != str(mobile) or str(to_be_recovered.user.email) != str(email):
                return render(request, 'recovery.html',
                              context={'recovery': f1, 'message': 'Provided details are wrong'})

            else:
                temp_password = generate_password()
                to_be_recovered.user.set_password(temp_password)
                to_be_recovered.save(force_update=True)
                recover_mail(email, temp_password)
                request.session.flush()
                return HttpResponseRedirect(reverse('user_login_page'), content_type=dict,
                                            content={'error': 'Temporary password is '
                                                              'sent to your email. '
                                                              'Check email register '
                                                              'email id'})

    return render(request, 'recovery.html',
                  context={'recovery': f1})


@login_required(login_url='home')
def call_download(request):
    cleanup()
    handler = file_handler.objects.filter(profile=request.user)
    if bool(handler.exists()):
        file_paths = []
        for i in handler:
            i.count += 1
            i.downloaded = True
            file_paths.append(str(i.files.path))
            i.save(update_fields=['count', 'downloaded'])
        path = get_zip_file(file_paths)
        with open(path, 'rb') as file:
            response = HttpResponse(file.read(), content_type='application/force-download')
            response['Content-Disposition'] = 'attachment; filename="%s"' % 'Download.zip'
            response['X-Sendfile'] = smart_str(path)
            return response
    return HttpResponseRedirect(reverse('user_success_page'))


@login_required(login_url='home')
def delete_download(request):
    cleanup()
    files = file_handler.objects.filter(profile=request.user)
    if bool(files.exists()):
        for file in files:
            os.remove(file.files.path)
            file.delete()

    return HttpResponseRedirect(reverse('user_success_page'))
