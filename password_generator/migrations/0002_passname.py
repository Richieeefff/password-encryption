# Generated by Django 4.2.5 on 2023-10-05 13:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('password_generator', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='passname',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200, null=True)),
                ('password', models.CharField(max_length=200, null=True)),
            ],
        ),
    ]
