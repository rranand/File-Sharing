import re

from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.encoding import smart_str
from ipware import get_client_ip

from LoginPortal.mail import generate_otp, recover_mail, generate_password
from .file_handling import *
from .forms import basic_detail, more_detail, login_form, change_password, search, otp_authentication, recover_password
from .models import info, file_handler, login_attempt, friends

otp = None


# Create your views here.

# ----------------------------------------------------------------------------------------------------------------------


def home(request):
    cleanup()
    if request.user.is_superuser:
        return HttpResponseRedirect(reverse('user_logout_page'))
    elif request.user.is_authenticated:
        return HttpResponseRedirect(reverse('user_success_page'))
    return render(request, 'home.html')


# ----------------------------------------------------------------------------------------------------------------------


def register(request):
    cleanup()

    if request.user.is_superuser:
        return HttpResponseRedirect(reverse('user_logout_page'))
    elif request.user.is_authenticated:
        return HttpResponseRedirect(reverse('user_success_page'))

    f1 = basic_detail()
    f2 = more_detail()

    if request.method == 'POST':
        f1 = basic_detail(request.POST)
        f2 = more_detail(request.POST)

        if f1.is_valid() and f2.is_valid():

            mobile = f2.cleaned_data['mobile']
            email = f1.cleaned_data['email']
            if info.objects.filter(mobile=mobile).exists() or info.objects.filter(user__email=email).exists():
                return render(request, 'register.html', {'form1': f1, 'form2': f2, 'user': request.user,
                                                         'error': 'This mobile number or email id is already registered'})

            basic_data = f1.save()
            basic_data.set_password(basic_data.password)
            basic_data.save()

            more_data = f2.save(commit=False)
            more_data.user = basic_data
            more_data.email = email
            more_data.mobile = mobile
            if 'profile_pic' in request.FILES:
                more_data.profile_pic = request.FILES['profile_pic']

            more_data.save()

            return render(request, 'home.html', context={'registered': True})

    return render(request, 'register.html', {'form1': f1, 'form2': f2, 'user': request.user})


# ----------------------------------------------------------------------------------------------------------------------


def user_login(request):
    cleanup()

    if request.user.is_superuser:
        return HttpResponseRedirect(reverse('user_logout_page'))
    elif request.user.is_authenticated:
        return HttpResponseRedirect(reverse('user_success_page'))

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
                                login_try.time) <= 3600 and login_try.count == 3:
                            remaining_time = int(3600 - int(int(time.time()) - int(login_try.time)))
                            message = 'You are still blocked!!! {0} minutes and {1} seconds left!!!'.format(
                                int(remaining_time // 60), int(remaining_time % 60))
                            return render(request, 'login.html', context={'error': message, 'login_form': f1})
                        login_try.time = 0
                        login_try.count = 0
                        login_try.ip, routable = get_client_ip(request)
                        login_try.save(update_fields=['count', 'time', 'ip'])
                        login(request, user)
                        return HttpResponseRedirect(reverse('user_success_page'))

                    elif user is None:
                        if not dont:
                            if login_try.count < 3:
                                login_try.count += 1
                                message = 'Authentication failed....Verify username and password ' + str(
                                    4 - int(login_try.count)) + ' attempt left!!!'
                            elif login_try.count == 3:
                                message = 'You have been blocked for 1 hour. Please Login after 1 hour'
                                login_try.time = int(time.time())
                                login_try.ip, routable = get_client_ip(request)
                            login_try.save(update_fields=['count', 'time', 'ip'])
                        else:
                            message = 'Authentication failed.... ' + str(username) + ' not found!!!'
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


# ----------------------------------------------------------------------------------------------------------------------


def logged_in(request):
    cleanup()
    global otp

    if request.user.is_superuser:
        return HttpResponseRedirect(reverse('user_logout_page'))

    try:
        profile = info.objects.get(user=request.user)
    except info.DoesNotExist:
        return render(request, 'dashboard.html', context={'error': 'Can\'t retrieve data from database'})
    except TypeError:
        return HttpResponseRedirect(reverse('home'))

    friends_request = friends.objects.filter(friend__user=request.user, accept=False)
    friends_list = friends.objects.filter(profile=profile, accept=True)
    friends_list = friends_list.union(friends.objects.filter(friend=profile, accept=True))
    check_files = file_handler.objects.filter(profile=profile.user)

    f2 = search()
    f3 = otp_authentication()
    f4 = basic_detail(instance=profile.user)
    f5 = more_detail(instance=profile)
    attribute_manager(f4, f5)
    mobile_num = profile.mobile

    if not profile.verified and len(str(otp)) != 6:
        otp = generate_otp(email=str(profile.user.email))

    if request.method == 'POST':
        f1 = change_password(data=request.POST)
        f2 = search(data=request.POST)
        f3 = otp_authentication(data=request.POST)

        # ----------------------------------------------------------------------------------------------------------------------

        # Change password

        if 'change_password' in request.POST:
            if profile == info.objects.get(user_id=request.POST.get('change_password')):
                return render(request, 'change_password.html',
                              context={'change_password': f1, 'search': f2, 'profile': profile})

        if f1.is_valid():
            cpass = f1.cleaned_data['current']
            npass = f1.cleaned_data['new_password']
            vpass = f1.cleaned_data['v_new_password']

            if type(cpass) == str:

                if request.user.check_password(str(cpass)):
                    if npass == vpass:
                        profile.user.set_password(str(npass))
                        profile.user.save(force_update=True, update_fields=['password', ])
                        request.session.flush()
                        return HttpResponseRedirect(reverse('user_success_page'))
                    else:
                        return render(request, 'change_password.html',
                                      context={'error': 'New Password is not typed correctly',
                                               'change_password': f1, 'search': f2, 'profile': profile})

                else:
                    return render(request, 'change_password.html',
                                  context={'error': 'Password is not valid',
                                           'change_password': f1, 'search': f2, 'profile': profile})

        # ----------------------------------------------------------------------------------------------------------------------

        # Search within the profile
        if f2.is_valid():
            search_profile = f2.cleaned_data['search_profile']
            try:
                branch_choose = str(int(f2.cleaned_data['choose_branch']) - 1)
            except ValueError:
                pass

            if str(search_profile) != str('#####'):

                if bool(re.search('[\d]{4,10}', str(search_profile))) or bool(
                        re.search('[@]{1}', str(search_profile))) or \
                        bool(re.search('^[a-zA-Z]{3,}$', str(search_profile))):

                    if int(branch_choose) == 0:
                        all_profiles = info.objects.filter(mobile__iregex=str(search_profile), verified=True).exclude(
                            user=profile.user)
                        all_profiles = all_profiles.union(info.objects.filter(
                            user__email__exact=str(search_profile), verified=True).exclude(user=profile.user), info.objects.filter(
                            user__first_name__contains=str(search_profile), verified=True).exclude(user=profile.user),
                                                          info.objects.filter(
                                                              user__last_name__contains=str(search_profile), verified=True).exclude(
                                                              user=profile.user))
                    else:
                        all_profiles = info.objects.filter(mobile__iregex=str(search_profile),
                                                           branch=branch_choose, verified=True).exclude(user=profile.user)
                        all_profiles = all_profiles.union(info.objects.filter(
                            user__email__exact=str(search_profile), branch=branch_choose, verified=True).exclude(user=profile.user),
                                                          info.objects.filter(
                                                              user__first_name__contains=str(search_profile),
                                                              branch=branch_choose, verified=True).exclude(user=profile.user),
                                                          info.objects.filter(
                                                              user__last_name__contains=str(search_profile),
                                                              branch=branch_choose, verified=True).exclude(user=profile.user))

                    if not all_profiles.exists():
                        return render(request, 'search.html', content_type=dict,
                                      context={'profile': profile, 'search': f2,
                                               'search_message': str(str(search_profile) + ' not found'),
                                               'searched': str(search_profile)})

                    else:
                        return render(request, 'search.html', content_type=dict,
                                      context={'profile': profile, 'search': f2,
                                               'result': all_profiles,
                                               'searched': str(search_profile)})

                else:
                    return render(request, 'search.html', content_type=dict,
                                  context={'profile': profile, 'search': f2,
                                           'search_message': 'Provide Correct Details',
                                           'searched': str(search_profile)})

        # ----------------------------------------------------------------------------------------------------------------------

        # Edit Given Details
        if 'edit_info' in request.POST:
            return render(request, 'profiles.html', context={'edit_mode': True,
                                                             'admin': True, 'basic': f4, 'more_detail': f5,
                                                             'logged_user': profile, 'search': f2})

        if 'edit_success' in request.POST:
            f5 = more_detail(data=request.POST or None, files=request.FILES, instance=profile)

            if f5.is_valid():
                update_mb = f5.save(commit=False)
                update_mb.mobile = int(mobile_num)
                update_mb.save()
                return render(request, 'profiles.html', context={'edit_mode': False,
                                                                 'admin': True, 'basic': f4, 'more_detail': f5,
                                                                 'logged_user': profile, 'search': f2,
                                                                 'message': 'Profile Update Successfully'})
            else:
                return render(request, 'profiles.html', context={'edit_mode': True,
                                                                 'admin': True, 'basic': f4, 'more_detail': f5,
                                                                 'logged_user': profile, 'search': f2,
                                                                 'message': 'Invalid details were given'})

        # ----------------------------------------------------------------------------------------------------------------------

        # Friend Request
        if 'receiver_profile' in request.POST:
            try:
                friend_request = friends.objects.create(profile=profile, friend=info.objects.get(
                    user_id=int(request.POST.get('receiver_profile'))))
                friend_request.save()
            except BaseException as e:
                pass

        # ----------------------------------------------------------------------------------------------------------------------

        # Friend Request Acceptance
        if 'to_be_accept' in request.POST:
            try:
                accepted = friends_request.get(
                    profile=info.objects.get(user__username=request.POST.get('to_be_accept')))
                accepted.accept = True
                accepted.save(update_fields=['accept', ])
            except friends.DoesNotExist:
                pass

        # ----------------------------------------------------------------------------------------------------------------------

        if 'not_to_be_accept' in request.POST:
            try:
                not_accepted = friends_request.get(
                    profile=info.objects.get(user__username=request.POST.get('not_to_be_accept')))
                not_accepted.delete()
            except friends.DoesNotExist:
                pass

        # ----------------------------------------------------------------------------------------------------------------------

        # Delete friends
        if 'un_friend' in request.POST:
            try:
                un_friend = friends.objects.get(
                    profile=profile, friend=info.objects.get(user_id=request.POST.get('un_friend')))
                un_friend.delete()
            except friends.DoesNotExist:
                try:
                    un_friend = friends.objects.get(
                        profile=info.objects.get(user_id=request.POST.get('un_friend')), friend=profile)
                    un_friend.delete()
                except friends.DoesNotExist:
                    pass

        # ----------------------------------------------------------------------------------------------------------------------

        # Show More Info
        if 'more_info' in request.POST:
            show_more = info.objects.get(user_id=request.POST.get('more_info'))

            if show_more == profile:
                return render(request, 'profiles.html', context={'profile': show_more, 'logged_user': profile,
                                                                 'search': f2, 'admin': True})

            return render(request, 'profiles.html',
                          context={'profile': show_more, 'logged_user': profile, 'search': f2})

        # ----------------------------------------------------------------------------------------------------------------------

        # Profile File Verification
        if not profile.verified:
            if f3.is_valid():
                key = f3.cleaned_data['key']
                if len(str(key)) == 6 and str(otp) == str(key):
                    profile.verified = True
                    profile.save(update_fields=['verified'])
                    otp = None
                    return render(request, 'dashboard.html', content_type=dict,
                                  context={'profile': profile, 'search': f2,
                                           'verification': 'Your account has been verified successfully',
                                           'friends_request': friends_request, 'friends_list': friends_list})
                else:
                    return render(request, 'dashboard.html', content_type=dict,
                                  context={'profile': profile, 'otp_verify': f3,
                                           'message': 'OTP is not valid...please verify your otp'})

        # ----------------------------------------------------------------------------------------------------------------------

        # File Upload Code
        if 'user_id' in request.POST:
            send_file = info.objects.get(user_id=int(request.POST.get('user_id')))
            if 'upload_files' in request.FILES:

                address = os.path.join(os.getcwd(),
                                       os.path.join('media', os.path.join('received', str(send_file.user.username))))
                try:
                    log = open(os.path.join(address, 'log.txt'), 'a')
                except FileNotFoundError:
                    if not os.path.exists(os.path.join(os.getcwd(), os.path.join('media', os.path.join('received', str(
                            send_file.user.username))))):
                        os.mkdir(os.path.join(os.getcwd(), os.path.join('media', os.path.join('received', str(
                            send_file.user.username)))))
                    log = open(os.path.join(address, 'log.txt'), 'w+')
                log.write(str(time.ctime(time.time())) + '\n')

                for file in request.FILES.getlist('upload_files'):
                    handler = file_handler(profile=send_file.user, files=file, time=int(time.time()),
                                           sent_by=request.user.username)
                    handler.save()
                    log.write('Filename: ' + str(handler.files.name) + '   <---->   ' + 'Size: ' +
                              str(handler.files.size) + '   <---->   ' + 'Sender: ' + str(handler.sent_by) + '\n')
                log.write('\n\n\n')
                log.close()
            return HttpResponseRedirect(reverse('user_success_page'))

    return render(request, 'dashboard.html', content_type=dict,
                  context={'profile': profile, 'search': f2, 'otp_verify': f3,
                           'friends_request': friends_request, 'friends_list': friends_list, 'files': check_files})


# ----------------------------------------------------------------------------------------------------------------------

# Logout Code
@login_required(login_url='home')
def user_logout(request):
    cleanup()
    logout(request)
    return render(request, 'home.html', context={'message': 'You logged out successfully.'})


# ----------------------------------------------------------------------------------------------------------------------

# Delete User Profile
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


# ----------------------------------------------------------------------------------------------------------------------

# Password Recovering Code
def password_recover(request):
    cleanup()

    if request.user.is_superuser:
        return HttpResponseRedirect(reverse('user_logout_page'))
    elif request.user.is_authenticated:
        return HttpResponseRedirect(reverse('user_success_page'))

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
                to_be_recovered.user.save(force_update=True, update_fields=['password', ])
                recover_mail(email, temp_password)
                request.session.flush()
                return HttpResponseRedirect(reverse('user_login_page'), content_type=dict,
                                            content={'error': 'Temporary password is '
                                                              'sent to your email. '
                                                              'Check email register '
                                                              'email id'})

    return render(request, 'recovery.html',
                  context={'recovery': f1})


# ----------------------------------------------------------------------------------------------------------------------


@login_required(login_url='home')
def call_download(request):
    cleanup()
    handler = file_handler.objects.filter(profile=request.user)

    if bool(handler.exists()):
        file_paths = []
        for i in handler:
            if not i.downloaded:
                file_paths.append(str(i.files.path))
            i.count += 1
            i.downloaded = True
            i.save(update_fields=['count', 'downloaded'])

        if len(file_paths) == 0:
            return HttpResponseRedirect(reverse('user_success_page'))

        path = get_zip_file(file_paths)

        with open(path, 'rb') as file:
            response = HttpResponse(file.read(), content_type='application/force-download')
            response['Content-Disposition'] = 'attachment; filename="%s"' % 'Download.zip'
            response['X-Sendfile'] = smart_str(path)
            return response

    return HttpResponseRedirect(reverse('user_success_page'))


# ----------------------------------------------------------------------------------------------------------------------


@login_required(login_url='home')
def delete_download(request):
    cleanup()
    path = ''
    files = file_handler.objects.filter(profile=request.user)

    if bool(files.exists()):
        for file in files:
            path = str(os.path.join(os.path.split(os.path.dirname(file.files.path))[0], 'Download.zip'))
            os.remove(file.files.path)
            file.delete()
    if os.path.exists(path):
        os.remove(path)

    return HttpResponseRedirect(reverse('user_success_page'))

# -----------------------------------------------------------------------------------------------------------------------
