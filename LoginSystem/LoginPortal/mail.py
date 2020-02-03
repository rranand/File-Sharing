from smtplib import SMTP
import random


def generate_password():
    get = 'abcdefghijklmnopqrstuvwxyz1234567890!@#&'
    password = ''
    for i in range(10):
        password += get[random.randint(0, len(get)-1)]
    return str(password)


def sendmail(email, otp):
    connect = SMTP('smtp.gmail.com', 587)
    connect.ehlo()
    connect.starttls()
    connect.login(str('rrohitanand3336@gmail.com'), str('**********'))
    content = 'Subject: ' + str('OTP for login portal') + '\n\n' + str('Your six digit OTP is ') + str(
        otp) + '\n\n' + 'Regards\nRohit Anand'
    connect.sendmail(str('rrohitanand3336@gmail.com'), str(email), content)
    connect.quit()


def generate_otp(email):
    otp = random.randrange(111111, 999999)
    sendmail(email, otp)
    return otp


def recover_mail(email, password):
    connect = SMTP('smtp.gmail.com', 587)
    connect.ehlo()
    connect.starttls()
    connect.login(str('rrohitanand3336@gmail.com'), str('qbkpstvmwfgswlec'))
    content = 'Subject: ' + str('Change Password') + '\n\n' + str('Your Temporary password is ') + str(
        password) + '\n\n' + str('Please login and change your temporary password') + '\n\n' + 'Regards\nRohit Anand'
    connect.sendmail(str('rrohitanand3336@gmail.com'), str(email), content)
    connect.quit()
