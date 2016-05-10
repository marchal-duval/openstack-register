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
