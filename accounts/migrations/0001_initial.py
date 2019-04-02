# Generated by Django 2.1.7 on 2019-04-02 12:46

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Remember_Me',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False, unique=True)),
                ('token', models.CharField(max_length=255, verbose_name='Refresh Token')),
                ('userid', models.PositiveIntegerField()),
            ],
        ),
    ]
