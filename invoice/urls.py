from django.urls import path
from . import views

urlpatterns = [
path('login',views.login, name='login'),
path('logout',views.logout, name='logout'),
path('dashboard',views.dashboard, name='dashboard'),
path('pythonestas',views.pythonestas, name='pythonestas'),
path('py_visualizations',views.py_visualizations, name='py_visualizations'),
path('process_Minings',views.process_Minings, name='process_Minings'),
path('securitys',views.securitys, name='securitys'),
path('invoices',views.invoices, name='invoices'),
path('products',views.products, name='products'),
path('clients',views.clients, name='clients'),

#Create URL Paths
path('invoices/create',views.createInvoice, name='create-invoice'),
path('invoices/create-build/<slug:slug>',views.createBuildInvoice, name='create-build-invoice'),
path('securitys/check_url',views.check_url, name='check_url'),
path('securitys/Open_Ports',views.Open_Ports, name='Open_Ports'),
path('securitys/Encrypt_Decrypt',views.Encrypt_Decrypt, name='Encrypt_Decrypt'),
path('pythonestas/py_sum',views.py_sum, name='py_sum'),
path('pythonestas/py_average',views.py_average, name='py_average'),
path('py_visualizations/plotting',views.plotting, name='plotting'),
path('py_visualizations/ml_Visua',views.ml_Visua, name='ml_Visua'),
#Delete an invoice
path('invoices/delete/<slug:slug>',views.deleteInvoice, name='delete-invoice'),

#PDF and EMAIL Paths
path('invoices/view-pdf/<slug:slug>',views.viewPDFInvoice, name='view-pdf-invoice'),
path('invoices/view-document/<slug:slug>',views.viewDocumentInvoice, name='view-document-invoice'),
path('invoices/email-document/<slug:slug>',views.emailDocumentInvoice, name='email-document-invoice'),

#Company Settings Page
path('company/settings',views.companySettings, name='company-settings'),
]
