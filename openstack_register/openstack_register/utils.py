#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

import os
import hashlib
from base64 import urlsafe_b64encode as encode
from base64 import urlsafe_b64decode as decode


def encode_password(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return '{SSHA}' + encode(h.digest() + salt)


def check_password(challenge_password, password):
    challenge_bytes = decode(challenge_password[6:])
    digest = challenge_bytes[:20]
    salt = challenge_bytes[20:]
    hr = hashlib.sha1(password)
    hr.update(salt)
    return digest == hr.digest()


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
