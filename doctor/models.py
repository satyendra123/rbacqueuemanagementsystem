from django.db import models

# Create your models here.
from django.db import models

class Department(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

class Doctor(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    specialty = models.CharField(max_length=255)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    availability = models.BooleanField(default=True)
    opd_no = models.IntegerField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


