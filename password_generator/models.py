from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Costumer(models.Model):
    user = models.OneToOneField(User, null=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, null=True)
    email = models.CharField(max_length=200, null=True)
    date_created = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self) :
        return self.name
    
class Passname(models.Model):
    name = models.ForeignKey(Costumer, null=True, on_delete=models.SET_NULL)
    title = models.CharField(max_length=200, null=True)
    password = models.CharField(max_length=200, null=True)
    
    def __str__(self):
        return self.title
    


    
