from django.db import models
from django.template.defaultfilters import slugify
from django.utils import timezone
from uuid import uuid4
from django.urls import reverse
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import r2_score
import seaborn as sns
import xlwings as xw


class Client(models.Model):
    GOVERNORATES = [
        ('Cairo', 'Cairo'),
        ('Alexandria', 'Alexandria'),
        ('Giza', 'Giza'),
        ('Qalyubia', 'Qalyubia'),
        ('Port Said', 'Port Said'),
        ('Suez', 'Suez'),
        ('Luxor', 'Luxor'),
        ('Dakahlia', 'Dakahlia'),
        ('Gharbia', 'Gharbia'),
        ('Asyut', 'Asyut'),
        ('Ismailia', 'Ismailia'),
        ('Faiyum', 'Faiyum'),
        ('Sharqia', 'Sharqia'),
        ('Aswan', 'Aswan'),
        ('Damietta', 'Damietta'),
        ('Beheira', 'Beheira'),
        ('Minya', 'Minya'),
        ('Beni Suef', 'Beni Suef'),
        ('Qena', 'Qena'),
        ('Sohag', 'Sohag'),
        ('Red Sea', 'Red Sea'),
        ('Monufia', 'Monufia'),
        ('Kafr el-Sheikh', 'Kafr el-Sheikh'),
        ('North Sinai', 'North Sinai'),
        ('Matrouh', 'Matrouh'),
        ]
        
    #Basic Fields.
    clientName = models.CharField(null=True, blank=True, max_length=200)
    addressLine1 = models.CharField(null=True, blank=True, max_length=200)
    clientLogo  = models.ImageField(default='default_logo.jpg', upload_to='company_logos')
    governorate = models.CharField(choices=GOVERNORATES, blank=True, max_length=100)
    postalCode = models.CharField(null=True, blank=True, max_length=10)
    phoneNumber = models.CharField(null=True, blank=True, max_length=100)
    emailAddress = models.CharField(null=True, blank=True, max_length=100)
    taxNumber = models.CharField(null=True, blank=True, max_length=100)

    #Utility fields
    uniqueId = models.CharField(null=True, blank=True, max_length=100)
    slug = models.SlugField(max_length=500, unique=True, blank=True, null=True)
    date_created = models.DateTimeField(blank=True, null=True)
    last_updated = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return '{} {} {}'.format(self.clientName, self.governorate, self.uniqueId)

    def get_absolute_url(self):
        return reverse('client-detail', kwargs={'slug': self.slug})
    
    def save(self, *args, **kwargs):
        if self.date_created is None:
            self.date_created = timezone.localtime(timezone.now())
        
        if self.uniqueId is None:
            self.uniqueId = str(uuid4()).split('-')[1]
            self.slug = slugify('{} {} {}'.format(self.clientName, self.governorate, self.uniqueId))

        self.slug = slugify('{} {} {}'.format(self.clientName, self.governorate, self.uniqueId))
        self.last_updated = timezone.localtime(timezone.now())
    
        super(Client, self).save(*args, **kwargs)

class Invoice(models.Model):
    TERMS = [
    ('15 days', '15 days'),
    ('30 days', '30 days'),
    ('60 days', '60 days'),
    ]

    STATUS = [
    ('CURRENT', 'CURRENT'),
    ('EMAIL_SENT', 'EMAIL_SENT'),
    ('OVERDUE', 'OVERDUE'),
    ('PAID', 'PAID'),
    ]

    title = models.CharField(null=True, blank=True, max_length=100)
    number = models.CharField(null=True, blank=True, max_length=100)
    dueDate = models.DateField(null=True, blank=True)
    paymentTerms = models.CharField(choices=TERMS, default='15 days', max_length=100)
    status = models.CharField(choices=STATUS, default='CURRENT', max_length=100)
    notes = models.TextField(null=True, blank=True)

    #RELATED fields
    client = models.ForeignKey(Client, blank=True, null=True, on_delete=models.SET_NULL)

    #Utility fields
    uniqueId = models.CharField(null=True, blank=True, max_length=100)
    slug = models.SlugField(max_length=500, unique=True, blank=True, null=True)
    date_created = models.DateTimeField(blank=True, null=True)
    last_updated = models.DateTimeField(blank=True, null=True)


    def __str__(self):
        return '{} {}'.format(self.number, self.uniqueId)
        
    def get_absolute_url(self):
        return reverse('invoice-detail', kwargs={'slug': self.slug})
     
    def save(self, *args, **kwargs):
        if self.date_created is None:
            self.date_created = timezone.localtime(timezone.now())
        if self.uniqueId is None:
            self.uniqueId = str(uuid4()).split('-')[1]
            self.slug = slugify('{} {}'.format(self.number, self.uniqueId))

        self.slug = slugify('{} {}'.format(self.number, self.uniqueId))
        self.last_updated = timezone.localtime(timezone.now())

        super(Invoice, self).save(*args, **kwargs)

class Product(models.Model):
    CURRENCY = [
    ('EGP', 'EGP'),
    ('$', 'USD'),
    ]

    title = models.CharField(null=True, blank=True, max_length=100)
    description = models.TextField(null=True, blank=True)
    quantity = models.FloatField(null=True, blank=True)
    price = models.FloatField(null=True, blank=True)
    currency = models.CharField(choices=CURRENCY, default='EGP', max_length=100)

    #Related Fields
    invoice = models.ForeignKey(Invoice, blank=True, null=True, on_delete=models.CASCADE)

    #Utility fields
    uniqueId = models.CharField(null=True, blank=True, max_length=100)
    slug = models.SlugField(max_length=500, unique=True, blank=True, null=True)
    date_created = models.DateTimeField(blank=True, null=True)
    last_updated = models.DateTimeField(blank=True, null=True)


    def __str__(self):
        return '{} {}'.format(self.title, self.uniqueId)


    def get_absolute_url(self):
        return reverse('product-detail', kwargs={'slug': self.slug})
      
    def save(self, *args, **kwargs):
        if self.date_created is None:
            self.date_created = timezone.localtime(timezone.now())
        if self.uniqueId is None:
            self.uniqueId = str(uuid4()).split('-')[1]
            self.slug = slugify('{} {}'.format(self.title, self.uniqueId))

        self.slug = slugify('{} {}'.format(self.title, self.uniqueId))
        self.last_updated = timezone.localtime(timezone.now())

        super(Product, self).save(*args, **kwargs)

class Settings(models.Model):
    GOVERNORATES = [
        ('Cairo', 'Cairo'),
        ('Alexandria', 'Alexandria'),
        ('Giza', 'Giza'),
        ('Qalyubia', 'Qalyubia'),
        ('Port Said', 'Port Said'),
        ('Suez', 'Suez'),
        ('Luxor', 'Luxor'),
        ('Dakahlia', 'Dakahlia'),
        ('Gharbia', 'Gharbia'),
        ('Asyut', 'Asyut'),
        ('Ismailia', 'Ismailia'),
        ('Faiyum', 'Faiyum'),
        ('Sharqia', 'Sharqia'),
        ('Aswan', 'Aswan'),
        ('Damietta', 'Damietta'),
        ('Beheira', 'Beheira'),
        ('Minya', 'Minya'),
        ('Beni Suef', 'Beni Suef'),
        ('Qena', 'Qena'),
        ('Sohag', 'Sohag'),
        ('Red Sea', 'Red Sea'),
        ('Monufia', 'Monufia'),
        ('Kafr el-Sheikh', 'Kafr el-Sheikh'),
        ('North Sinai', 'North Sinai'),
        ('Matrouh', 'Matrouh'),
        ]

    #Basic Fields
    clientName = models.CharField(null=True, blank=True, max_length=200)
    clientLogo = models.ImageField(default='default_logo.jpg', upload_to='company_logos')
    addressLine1 = models.CharField(null=True, blank=True, max_length=200)
    governorate = models.CharField(choices=GOVERNORATES, blank=True, max_length=100)
    postalCode = models.CharField(null=True, blank=True, max_length=10)
    phoneNumber = models.CharField(null=True, blank=True, max_length=100)
    emailAddress = models.CharField(null=True, blank=True, max_length=100)
    taxNumber = models.CharField(null=True, blank=True, max_length=100)
    
    #Utility fields
    uniqueId = models.CharField(null=True, blank=True, max_length=100)
    slug = models.SlugField(max_length=500, unique=True, blank=True, null=True)
    date_created = models.DateTimeField(blank=True, null=True)
    last_updated = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return '{} {} {}'.format(self.clientName, self.governorate, self.uniqueId)
    
    def get_absolute_url(self):
        return reverse('settings-detail', kwargs={'slug': self.slug})
   
    def save(self, *args, **kwargs):
        if self.date_created is None:
            self.date_created = timezone.localtime(timezone.now())
        if self.uniqueId is None:
            self.uniqueId = str(uuid4()).split('-')[1]
            self.slug = slugify('{} {} {}'.format(self.clientName, self.governorate, self.uniqueId))

        self.slug = slugify('{} {} {}'.format(self.clientName, self.governorate, self.uniqueId))
        self.last_updated = timezone.localtime(timezone.now())

        super(Settings, self).save(*args, **kwargs)

class Visualization(models.Model):
    class Meta:
        verbose_name_plural = 'Visualization'

    def __str__(self):
        return self.Visualization
 
    
class Process_Minings(models.Model):
    class Meta:
        verbose_name_plural = 'Process_Minings'

    def __str__(self):
        return self.Process_Minings
    
class Pythonestas(models.Model):
    class Meta:
        verbose_name_plural = 'Pythonestas'

    def __str__(self):
        return self.Pythonestas

    
class Security(models.Model):
    class Meta:
        verbose_name_plural = 'Security'

    def __str__(self):
        return self.Security   