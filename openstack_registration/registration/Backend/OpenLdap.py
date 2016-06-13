#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

import ldap
import ldap.sasl
from registration.models import UserActivation


class OpenLdap(object):
    def __init__(self,
                 config):
        super(OpenLdap, self).__init__()
        self.global_config = config
        self.server = self.global_config['LDAP_SERVER']
        self.user = self.global_config['LDAP_USER']
        self.password = self.global_config['LDAP_PASSWORD']
        self.base_ou = self.global_config['LDAP_BASE_OU']
        self.connection = ldap.initialize(self.server)

        try:
            self.connection.simple_bind_s(self.user, self.password)
        except:
            print 'error during openLdap connection'

    def add_user(self,
                 username,
                 email,
                 firstname,
                 lastname,
                 password):
        """

        :param username:
        :param email:
        :param firstname:
        :param lastname:
        :param password:
        :return:
        """
        attributes = []
        dn_user = "uid={},ou=users,o=cloud".format(username)
        attrs = {
            'objectClass': ['organizationalPerson', 'person', 'inetOrgPerson', 'top'],
            'uid': username,
            'mail': email,
            'givenName': firstname,
            'sn': lastname,
            'cn': "{} {}".format(firstname, lastname),
            'userPassword': str(password),
            'pager': '514'
        }

        for value in attrs:
            entry = (value, attrs[value])
            attributes.append(entry)

        try:
            self.connection.add_s(dn_user, attributes)
        except:
            exit(1)

    def search_user(self,
                    uid=None,
                    mail=None,
                    attributes=None,
                    password=None):
        if uid is not None:
            return self.connection.search_s(self.base_ou,
                                            ldap.SCOPE_SUBTREE,
                                            "(&(objectClass=person)(uid={}))"
                                            .format(uid),
                                            ['uid'])

        elif mail is not None:
            return self.connection.search_s(self.base_ou,
                                            ldap.SCOPE_SUBTREE,
                                            "(&(objectClass=person)(mail={}))"
                                            .format(mail),
                                            ['mail'])
        elif attributes is not None:
            return self.connection.search_s(self.base_ou,
                                            ldap.SCOPE_SUBTREE,
                                            "(&(objectClass=person)(uid={}))"
                                            .format(attributes),
                                            ['uid', 'mail', 'givenName', 'sn', 'cn'])
        elif password is not None:
            return self.connection.search_s(self.base_ou,
                                            ldap.SCOPE_SUBTREE,
                                            "(&(objectClass=person)(uid={}))"
                                            .format(password),
                                            ['userPassword'])

    def enable_user(self,
                    uuid):
        attrs = {}
        user = UserActivation.objects.filter(link=uuid)

        if user:
            username = user[0].username
            user_attributes = self.search_user(attributes=username)
            dn_user = str(user_attributes[0][0])
            email = str(user_attributes[0][1]['mail'][0])
            firstname = str(user_attributes[0][1]['givenName'][0])
            lastname = str(user_attributes[0][1]['sn'][0])
            update_attrs = [(ldap.MOD_REPLACE, 'pager', '512')]
            attrs['mail'] = email
            attrs['username'] = username
            attrs['firstname'] = firstname
            attrs['lastname'] = lastname

            self.connection.modify_s(dn_user, update_attrs)
            user.delete()

        return attrs

    def change_user_password(self,
                             user,
                             password):
        attrs = {}
        user_attributes = self.search_user(attributes=user)
        dn_user = str(user_attributes[0][0])
        update_attrs = [(ldap.MOD_REPLACE, 'userPassword', password)]

        try:
            self.connection.modify_s(dn_user, update_attrs)
            attrs['status'] = 'success'
        except:
            attrs['status'] = 'fail'
        return attrs



