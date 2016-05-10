#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib import auth
from settings import LOGIN_REDIRECT_URL, GLOBAL_CONFIG
from Backend import OpenLdap
from utils import *


def login(request):
    """

    :param request:
    :return:
    """
    redirect_page = LOGIN_REDIRECT_URL
    if request.method == "POST":
        user = auth.authenticate(username=request.POST['username'],
                                 password=request.POST['password'])
        if user is not None:
            auth.login(request, user)
            return HttpResponseRedirect(redirect_page)
        else:
            return render(request, "login.html")
    else:
        return render(request, "login.html")


def home_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'home_get_html.html')


def policies_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'policies_get_html.html')


def register_dispatcher(request):
    if 'format' in request.GET:
        pass
    else:
        return render(request, 'register_get_html.html')
