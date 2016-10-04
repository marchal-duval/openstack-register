#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseRedirect, QueryDict
from django.contrib.auth.decorators import login_required
from django.contrib import auth
from openstack_registration.settings import GLOBAL_CONFIG
from Backend import OpenLdap
from registration.exceptions import InvalidX500DN
from registration.models import *
from utils import *


def user_is_authenticate(request):
    """

    :param request:
    :return:
    """
    data = {}
    data['status'] = 'False'
    if request.user.is_authenticated():
        data['status'] = 'True'
        data['user'] = str(request.user)
    return JsonResponse(data)


def user_is_group_admin(request,
                        type=None):
    """

    :param request:
    :param type:
    :return:
    """
    data = {}
    group_list = []
    data['status'] = 'False'
    data['admin'] = 'False'

    is_admin = GroupInfo.objects.filter(administrators__username=request.user)
    if is_admin:
        for each in is_admin:
            group_list.append(str(each.group_name))
        data['admin'] = group_list
        data['status'] = 'True'

    if type == 'python':
        return data
    else:
        return JsonResponse(data)


def login(request):
    """

    :param request:
    :return:
    """
    info = {}

    if request.user.is_authenticated():
        redirect_page = "/users/{}".format(request.user)
        return redirect(redirect_page)
    else:
        if request.method == "POST":
            user = auth.authenticate(username=request.POST['username'].lower(),
                                     password=request.POST['password'])
            if user is not None:
                redirect_page = "/users/{}".format(request.POST['username'].lower())
                auth.login(request, user)
                return HttpResponseRedirect(redirect_page)
            else:
                info['info'] = 'Your login/password are wrong'
                return render(request, "login.html", context=info)
        else:
            return render(request, "login.html")


def logout(request):
    """
    Logout user and redirect to login page

    :param request: HTTP request
    :return: HTTP
    """
    auth.logout(request)
    return redirect('/')


@login_required()
def user_dispatcher(request):
    """

    :param request:
    :return:
    """
    uri = request.path
    url_user = "/users/{}".format(request.user)

    if uri != url_user:
        return HttpResponseRedirect(url_user)
    else:
        if request.method == 'GET'\
                and 'format' in request.GET\
                and request.GET['format'] == 'json':
            return user_get_json(request)
        elif request.method == 'GET':
            return render(request, 'user_get_html.html')


@login_required()
def groups_dispatcher(request):
    """

    :param request:
    :return:
    """
    if request.method == 'GET'\
            and 'format' in request.GET\
            and request.GET['format'] == 'json'\
            and user_is_group_admin(request, type='python')['admin'] != 'False':
            # and request.path in user_is_group_admin(request, type='python')['admin']:

        return groups_get_json(request)
    elif request.method == 'GET'\
            and user_is_group_admin(request, type='python')['admin'] != 'False':
        return groups_get_html(request)
    else:
        return redirect('/')


@login_required()
def group_dispatcher(request):
    """

    :param request:
    :return:
    """
    if request.method == 'GET'\
            and 'format' in request.GET\
            and request.GET['format'] == 'json'\
            and user_is_group_admin(request, type='python')['admin'] != 'False'\
            and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin']:
        return group_get_json(request)
    elif request.method == 'GET'\
            and user_is_group_admin(request, type='python')['admin'] != 'False'\
            and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin']:
        return group_get_html(request)
    else:
        return redirect('/')

@login_required()
def group_get_json(request):
    """

    :param request:
    :return:
    """
    data = {}
    ldap = OpenLdap(GLOBAL_CONFIG)
    attrs = ldap.search_group(request.path_info.split('/')[2])
    data['attrs'] = {}
    for key, value in attrs:
        for each in value:
            data['attrs'][each] = value[each]

    return JsonResponse(data)


@login_required()
def group_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'group_get_html.html')


@login_required()
def user_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'user_get_html.html')


@login_required()
def user_get_json(request):
    """

    :param request:
    :return:
    """
    data = {}
    ldap = OpenLdap(GLOBAL_CONFIG)
    attrs = ldap.search_user(attributes=request.user)
    data['attrs'] = {}

    # attrs = attrs[0][1]
    for key, value in attrs:
        for each in value:
            data['attrs'][each] = value[each]

    return JsonResponse(data)


def home_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'home_get_html.html')


@login_required()
def groups_get_html(request):
    """

    :param request:
    :return:
    """
    data = user_is_group_admin(request, type='python')
    if data['status'] != 'True':
        return redirect('/')
    else:
        return render(request, 'groups_get_html.html')


@login_required()
def groups_get_json(request):
    data = {}
    is_admin = user_is_group_admin(request, type='python')
    groups = []
    for each in is_admin['admin']:
        groups.append(each)

    data['groups'] = groups
    return JsonResponse(data)


def policies_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'policies_get_html.html')


def register_dispatcher(request):
    if 'format' in request.GET:
        if 'adduser' in request.GET:
            attributes = QueryDict(request.body).dict()
            add_user(request, attributes)
            return JsonResponse(attributes)
    else:
        return render(request, 'register_get_html.html')


def attributes_dispatcher(request):
    attributes = {}
    if 'password' in request.GET:
        password = request.GET['password']
        attributes = check_password_constraints(password)
        return JsonResponse(attributes)

    if 'checkPassword' in request.GET:
        ldap = OpenLdap(GLOBAL_CONFIG)
        password = unicode(request.GET['checkPassword']).encode(encoding='utf-8')
        uid = str(request.user)
        userPassword = ldap.search_user(password=uid)

        userPassword = userPassword[0][1]['userPassword'][0]
        checked = check_password(userPassword, password)

        if checked:
            attributes['status'] = 'success'
        else:
            attributes['status'] = 'fail'
        return JsonResponse(attributes)

    if 'changePassword' in request.GET:
        info = {}
        attributes = QueryDict(request.body).dict()
        ldap = OpenLdap(GLOBAL_CONFIG)
        uid = str(request.user)
        password = encode_password(unicode(attributes['changePassword'])
                                   .encode(encoding='utf-8'))
        try:
            attrs = ldap.change_user_password(uid, password)
            return JsonResponse(attrs)
        except:
            info['info'] = 'Fail to change your password.'
            return render(request, 'error_get_html.html', context=info)
        # return render(request, 'home_get_html.html')

    ### TEST ###
    elif 'passwords' in request.GET:
        password = request.GET['passwords']
        attributes['password'] = encode_password(password)
        print type(password)
        print password
        print type(attributes['password'])
        print attributes['password']
        # return JsonResponse(attributes)
        return render(request, 'users_get_html.html')
    ### END ###

    elif 'uid' in request.GET:
        ldap = OpenLdap(GLOBAL_CONFIG)
        uid = normalize_string(request.GET['uid'])
        checked = ldap.search_user(uid=uid)
        attributes['uid'] = uid

        if checked:
            attributes['status'] = 'fail'
        else:
            attributes['status'] = 'success'
        return JsonResponse(attributes)

    elif 'firstname' in request.GET:
        firstname = normalize_string(request.GET['firstname'], option='name')
        lastname = normalize_string(request.GET['lastname'], option='name')
        attributes['firstname'] = firstname
        attributes['lastname'] = lastname
        return JsonResponse(attributes)

    elif 'mail' in request.GET:
        ldap = OpenLdap(GLOBAL_CONFIG)
        mail = request.GET['mail']
        checked = ldap.search_user(mail=mail)

        if checked:
            attributes['status'] = 'fail'
        else:
            attributes['status'] = 'success'
        return JsonResponse(attributes)


def add_user(request,
             attributes):
    GLOBAL_CONFIG['project'] = ''
    ldap = OpenLdap(GLOBAL_CONFIG)
    username = str(attributes['username'])
    email = str(attributes['email'])
    firstname = str(attributes['firstname'])
    lastname = str(attributes['lastname'])
    x500dn = str(attributes['x500dn'])
    GLOBAL_CONFIG['project'] = str(attributes['project'])
    password = encode_password(unicode(attributes['password']).encode(encoding='utf-8'))

    try:
        ldap.add_user(username, email, firstname, lastname, x500dn, password)
    except InvalidX500DN:
        exit(1)
    send_mail(username, firstname, lastname, email, '', '', 'add')


def activate_user(request):
    uuid = request.path.split('/action/')
    uuid.pop(0)
    uuid = str(uuid[0])
    ldap = OpenLdap(GLOBAL_CONFIG)
    info = {}
    try:
        attrs = ldap.enable_user(uuid)
        send_mail(attrs['username'], attrs['firstname'], attrs['lastname'],
                  attrs['mail'], GLOBAL_CONFIG['project'],
                  'marchal@lal.in2p3.fr', 'enable')
                  # GLOBAL_CONFIG['admin'], 'enable')
    except:
        info['info'] = 'Your account is already enable or the url is not ' \
                          'valid, please check your mailbox.'
        return render(request, 'error_get_html.html', context=info)
    return render(request, 'home_get_html.html')
