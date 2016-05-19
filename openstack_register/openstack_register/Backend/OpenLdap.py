#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

import ldap
import ldap.sasl


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
            'userPassword': str(password)
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
                    mail=None):
        if uid is not None:
            return self.connection.search_s(self.base_ou,
                                            ldap.SCOPE_SUBTREE,
                                            "(&(objectClass=person)(uid={}))"
                                            .format(uid),
                                            ['uid'])

        if mail is not None:
            return self.connection.search_s(self.base_ou,
                                            ldap.SCOPE_SUBTREE,
                                            "(&(objectClass=person)(mail={}))"
                                            .format(mail),
                                            ['mail'])
