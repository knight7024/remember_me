from django.db import models

# Create your models here.

class Remember_Me(models.Model):
    id = models.AutoField(primary_key=True, unique=True)
    token = models.CharField(verbose_name='Refresh Token', max_length=255)
    userid = models.PositiveIntegerField()
    # expires = models.DateTimeField(verbose_name='Expired at')