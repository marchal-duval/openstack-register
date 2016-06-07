from __future__ import unicode_literals

from django.db import models


# Create your models here.
class UserActivation(models.Model):
    link = models.TextField(null=False)
    username = models.CharField(max_length=32, null=False)
    expiration_date = models.DateField(auto_now_add=True, auto_now=False)
