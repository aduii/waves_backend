from django.db import models

# Create your models here.

class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    password = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class Report(models.Model):
    name = models.CharField(max_length=100)
    date = models.DateTimeField()
    ip = models.CharField(max_length=100, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

class Vulnerability(models.Model):
    cveCode = models.CharField(max_length=100)
    description = models.TextField(null=True)
    exploit = models.TextField(null=True)
    exploitLink = models.URLField(null=True)
    impact = models.FloatField()

    report = models.ForeignKey(Report, on_delete=models.CASCADE)

    def __str__(self):
        return self.cveCode