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

    def AddUser(self):
        pass
