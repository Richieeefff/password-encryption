# password_generator/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.encrypt, name='generate_password'),
    path('decrypt/', views.decrypt, name='decrypt'),
    path('viewpassword/', views.viewpassword, name='viewpassword'),
    path('register/', views.registerPage, name="register"),
    path('login/', views.loginPage, name= 'login'),
    path('logout/', views.loginPage, name= 'logout'),
    path('create_pass/', views.createPass, name='create_pass'),
    path('update_pass/', views.updatePass, name='update_pass')
]
