#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

import os
import hashlib
import unicodedata
import re
from base64 import urlsafe_b64encode as encode
from base64 import urlsafe_b64decode as decode
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import uuid
from models import UserActivation


# def encode_password(password):
#     salt = os.urandom(4)
#     h = hashlib.sha1(password)
#     h.update(salt)
#     return '{SSHA}' + encode(h.digest() + salt)

def encode_password(password):
    """
    Encodes the given password as a base64 SSHA hash+salt buffer
    :param password:
    """
    salt = os.urandom(4)

    # hash the password and append the salt
    sha = hashlib.sha1(password)
    sha.update(salt)

    # create a base64 encoded string of the concatenated digest + salt
    digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()

    # now tag the digest above with the {SSHA} tag
    tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)

    return tagged_digest_salt


def check_password(tagged_digest_salt, password):
    """
    Checks the OpenLDAP tagged digest against the given password
    :param tagged_digest_salt:
    :param password:
    """
    # the entire payload is base64-encoded
    assert tagged_digest_salt.startswith('{SSHA}')

    # strip off the hash label
    digest_salt_b64 = tagged_digest_salt[6:]

    # the password+salt buffer is also base64-encoded.  decode and split the
    # digest and salt
    digest_salt = digest_salt_b64.decode('base64')
    digest = digest_salt[:20]
    salt = digest_salt[20:]

    sha = hashlib.sha1(password)
    sha.update(salt)

    return digest == sha.digest()


# def check_password(challenge_password, password):
#     challenge_bytes = decode(challenge_password[6:])
#     digest = challenge_bytes[:20]
#     salt = challenge_bytes[20:]
#     hr = hashlib.sha1(password)
#     hr.update(salt)
#     return digest == hr.digest()


def check_password_constraints(password):
    """

    :param password:
    :return:
    """
    attributes = {}
    # password = request.GET['password']
    constraint = {'lower': False,
                  'upper': False,
                  'spe': False,
                  'number': False}
    index = 0
    total = 0
    taille = len(password)
    spe = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+',
           '{', '}', '"', ':', ';', '\', ''', '[', ']', '<', '>']

    while index < taille:
        var = password[index]
        if var.islower():
            constraint['lower'] = True
        if var.isupper():
            constraint['upper'] = True
        if var in spe:
            constraint['spe'] = True
        if var.isdigit():
            constraint['number'] = True
        index += 1

    if constraint['lower']:
        total += 1
    if constraint['upper']:
        total += 1
    if constraint['spe']:
        total += 1
    if constraint['number']:
        total += 1

    if len(password) < 8:
        attributes['check'] = 'character'
    elif total < 3:
        attributes['check'] = 'require'
    elif len(password) >= 8 and total >= 3:
        attributes['check'] = 'success'
    else:
        attributes['check'] = 'error'
    return attributes


def normalize_string(string):
    """

    :param string:
    :return:
    """
    return re.sub('_', '',
                  re.sub(r'[\W, 0-9]', '',
                         unicodedata.normalize('NFKD', string).encode('ASCII', 'ignore').lower()))


def send_mail(username,
              user_email,
              admin_mail,
              action):
    """

    :param username:
    :param user_email:
    :param admin_mail:
    :return:
    """
    message = ''
    header = MIMEMultipart()
    header['From'] = 'no-reply@openstack.lal.in2p3.fr'
    header['To'] = user_email
    header['Subject'] = 'OpenStack Registration Message'

    if action == 'add':
        random_string = uuid.uuid4()
        link = "http://134.158.76.228:8000/action/{}".format(random_string)

        message = "Dear {}, \n\nYou just create an account on OpenStack@lal.\n" \
                  "Please follow the ling to activate your account: \n{}" \
                  "\n\nDon't reply at this email.".format(username,
                                                          link)
        add_entry_database(random_string, username)

    elif action == 'enable':
        message = "Dear {}, \n\nYour account have been enabled." \
                  "\n\nDon't reply at this email.".format(username)

    header.attach(MIMEText(message))
    mail_server = smtplib.SMTP('smtp.lal.in2p3.fr', 25)
    mail_server.sendmail('root', 'marchal@lal.in2p3.fr',
                         header.as_string())
    # replace marchal@.. by user_email
    mail_server.quit()



def add_entry_database(random_string,
                       user):
    new_user = UserActivation(link=random_string, username=user)
    new_user.save()
