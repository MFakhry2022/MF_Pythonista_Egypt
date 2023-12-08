from django.test import TestCase
from django.urls import reverse
from .models import *
from .views import *
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.test import Client
from django.core import mail

class ArticleViewTestCase(TestCase):
    def test_article_create(self):
        User.objects.create(username='', password=make_password('topsecret'))
        logged_in = self.client.login(username='', password="topsecret")
        self.assertTrue(logged_in)

class ClientModelTests(TestCase):
    def test_client_str(self):
        client = Client(clientName = '', addressLine1 = '', clientLogo  = '', governorate = '', postalCode = '', phoneNumber = '', emailAddress = '', taxNumber = '')
        self.assertTrue(client)

class InvoiceModelTests(TestCase):
    def test_invoice_str(self):
        invoice = Invoice(title = '', number = '', dueDate = '', paymentTerms = '', status = '', notes = '')
        self.assertTrue(invoice)
        
class ProductModelTests(TestCase):
    def test_product_str(self):
        product = Product(title = '', description = '', quantity = '', price = '', currency = '')
        self.assertTrue(product)
        
class SettingsModelTests(TestCase):
    def test_settings_str(self):
        settings = Settings(clientName = '', clientLogo = '', addressLine1 = '', governorate = '', postalCode = '', phoneNumber = '', emailAddress = '', taxNumber ='')
        self.assertTrue(settings)     
       

class loginViewsTests(TestCase):
    def test_login_view(self):
        response = self.client.get(reverse('login'))
        self.assertTrue(response.status_code, 200)

class DashboardViewsTests(TestCase):
    def test_dashboard_view(self):
        response = self.client.get(reverse('dashboard'))
        self.assertTrue(response.status_code, 200)

class InvoicesViewsTests(TestCase):
    def test_invoices_view(self):
        response = self.client.get(reverse('invoices'))
        self.assertTrue(response.status_code, 200)
     
class ProductsViewsTests(TestCase):
    def test_products_view(self):
        response = self.client.get(reverse('products'))
        self.assertTrue(response.status_code, 200)
         
class ClientsViewsTests(TestCase):
    def test_clients_view(self):
        response = self.client.get(reverse('clients'))
        self.assertTrue(response.status_code, 200)
      
class LogoutViewsTests(TestCase):
    def test_logout_view(self):
        response = self.client.get(reverse('logout'))
        self.assertTrue(response.status_code, 200)
      
from django.test import TestCase, modify_settings


class MiddlewareTestCase(TestCase):
    @modify_settings(
        MIDDLEWARE={
            "append": "django.middleware.cache.FetchFromCacheMiddleware",
            "prepend": "django.middleware.cache.UpdateCacheMiddleware",
        }
    )
    def test_cache_middleware(self):
        response = self.client.get("/")


class EmailTest(TestCase):
    def test_send_email(self):
        # Send message.
        mail.send_mail(
            "Subject here",
            "Here is the message.",
            "from@example.com",
            ["to@example.com"],
            fail_silently=False,
        )

        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)

        # Verify that the subject of the first message is correct.
        self.assertEqual(mail.outbox[0].subject, "Subject here") 
        
