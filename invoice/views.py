from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from .forms import *
from .models import *
from .functions import *
from django.contrib.auth.models import auth
from uuid import uuid4
from django.http import HttpResponse
import pdfkit
from django.template.loader import get_template
import os
from django.shortcuts import render
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import r2_score
from sklearn.ensemble import RandomForestRegressor
from sklearn import tree

# data
import pandas as pd
from pm4py.objects.conversion.log import converter as log_converter
from pm4py.objects.log.importer.xes import importer as xes_importer
from pm4py.objects.log.util import dataframe_utils
# process mining
from pm4py.algo.discovery.alpha import algorithm as alpha_miner
from pm4py.algo.discovery.inductive import algorithm as inductive_miner
from pm4py.algo.discovery.heuristics import algorithm as heuristics_miner
from pm4py.algo.discovery.dfg import algorithm as dfg_discovery
# viz
from pm4py.visualization.petri_net import visualizer as pn_visualizer
from pm4py.visualization.process_tree import visualizer as pt_visualizer
from pm4py.visualization.heuristics_net import visualizer as hn_visualizer
from pm4py.visualization.dfg import visualizer as dfg_visualization
# misc
from pm4py.objects.conversion.process_tree import converter as pt_converter

import tkinter as tk
from tkinter import simpledialog
from statistics import mean
import numpy as np
import requests
import validators
import socket
import subprocess
import platform
import math
import string
import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
#Anonymous required
def anonymous_required(function=None, redirect_url=None):

   if not redirect_url:
       redirect_url = 'dashboard'

   actual_decorator = user_passes_test(
       lambda u: u.is_anonymous,
       login_url=redirect_url
   )

   if function:
       return actual_decorator(function)
   return actual_decorator


def index(request):
    context = {}
    return render(request, 'invoice/index.html', context)


@anonymous_required
def login(request):
    context = {}
    if request.method == 'GET':
        form = UserLoginForm()
        context['form'] = form
        return render(request, 'invoice/login.html', context)

    if request.method == 'POST':
        form = UserLoginForm(request.POST)

        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)

            return redirect('dashboard')
        else:
            context['form'] = form
            messages.error(request, 'Invalid Credentials')
            return redirect('login')


    return render(request, 'invoice/login.html', context)


@login_required
def dashboard(request):
    pythonestas = Pythonestas.objects.all().count()
    py_visualizations = Visualization.objects.all().count()
    process_Minings = Process_Minings.objects.all().count()
    securitys = Security.objects.all().count()
    clients = Client.objects.all().count()
    invoices = Invoice.objects.all().count()
    paidInvoices = Invoice.objects.filter(status='PAID').count()


    context = {}
    context['pythonestas'] = pythonestas
    context['py_visualizations'] = py_visualizations
    context['process_Minings'] = process_Minings
    context['securitys'] = securitys
    context['clients'] = clients
    context['invoices'] = invoices
    context['paidInvoices'] = paidInvoices
    return render(request, 'invoice/dashboard.html', context)

@login_required
def pythonestas(request):
    context = {}
    pythonestas = Pythonestas.objects.all()
    context['pythonestas'] = pythonestas
    return render(request, 'invoice/pythonestas.html', context)



@login_required
def py_visualizations(request):   
    context = {}
    py_visualizations = Visualization.objects.all()
    context['py_visualizations'] = py_visualizations   
    return render(request, 'invoice\py_visualizations.html', context)

@login_required
def process_Minings(request):
    context = {}
    process_Minings = Process_Minings.objects.all()
    context['process_Minings'] = process_Minings
    
    # Open the spreadsheet document
    #wk = xw.books.open(r'running-example.xlsx')
    #sheet = wk.sheets("running")
    
    # Use excelwings to manipulate the excel workbook
    book=xw.Book('running-example.xlsx')
    sheet=book.sheets('running')
    
    # Loading the data
    # XES
    log = xes_importer.apply('running-example.xes')
    df = pd.read_excel('running-example.xlsx')
    df = dataframe_utils.convert_timestamp_columns_in_df(df)
    df = df.sort_values('time:timestamp')
    log = log_converter.apply(df)
    df.sort_values(['case:concept:name', 'time:timestamp']).reset_index(drop=True)
    # Process Mining
    # Alpha Miner
    net, initial_marking, final_marking = alpha_miner.apply(log)
    # viz
    gviz = pn_visualizer.apply(net, initial_marking, final_marking)  
    # Save the figure in the Excel
    sheet=gviz.view()
    # copy the figure in Excel sheet
    xw.sheets.active.pictures.add(sheet,name='Alpha Miner',update=True)

    # add information about frequency to the viz
    parameters = {pn_visualizer.Variants.FREQUENCY.value.Parameters.FORMAT: "png"}
    gviz = pn_visualizer.apply(net, initial_marking, final_marking,
                            parameters=parameters,
                            variant=pn_visualizer.Variants.FREQUENCY,
                            log=log)
    # save the Petri net
    sheet=gviz.view()
    xw.sheets.active.pictures.add(sheet,name='Frequency',update=True)
    # Directly-Follows Graph
    # creatig the graph from log
    dfg = dfg_discovery.apply(log)
    # viz
    gviz = dfg_visualization.apply(dfg, log=log, variant=dfg_visualization.Variants.FREQUENCY)
    sheet=gviz.view()
    xw.sheets.active.pictures.add(sheet,name='Follows Graph',update=True)
    # creatig the graph from log
    dfg = dfg_discovery.apply(log, variant=dfg_discovery.Variants.PERFORMANCE)
    # viz
    gviz = dfg_visualization.apply(dfg, log=log, variant=dfg_visualization.Variants.PERFORMANCE)
    sheet=gviz.view()
    xw.sheets.active.pictures.add(sheet,name='Graph from log',update=True)
    
    
    context = {
        'df': df,
        'net': net,
        'dfg': dfg,
    }

    return render(request, 'invoice/process_Minings.html', context)

@login_required
def securitys(request):
    context = {}
    securitys = Security.objects.all()
    context['securitys'] = securitys
    
    return render(request, 'invoice/securitys.html', context)

@login_required
def invoices(request):
    context = {}
    invoices = Invoice.objects.all()
    context['invoices'] = invoices

    return render(request, 'invoice/invoices.html', context)


@login_required
def products(request):
    context = {}
    products = Product.objects.all()
    context['products'] = products

    return render(request, 'invoice/products.html', context)



@login_required
def clients(request):
    context = {}
    clients = Client.objects.all()
    context['clients'] = clients

    if request.method == 'GET':
        form = ClientForm()
        context['form'] = form
        return render(request, 'invoice/clients.html', context)

    if request.method == 'POST':
        form = ClientForm(request.POST, request.FILES)

        if form.is_valid():
            form.save()

            messages.success(request, 'New Client Added')
            return redirect('clients')
        else:
            messages.error(request, 'Problem processing your request')
            return redirect('clients')


    return render(request, 'invoice/clients.html', context)



@login_required
def logout(request):
    auth.logout(request)
    return redirect('login')


###--------------------------- Create Invoice Views Start here --------------------------------------------- ###

@login_required
def createInvoice(request):
    #create a blank invoice ....
    number = 'INV-'+str(uuid4()).split('-')[1]
    newInvoice = Invoice.objects.create(number=number)
    newInvoice.save()

    inv = Invoice.objects.get(number=number)
    return redirect('create-build-invoice', slug=inv.slug)




def createBuildInvoice(request, slug):
    #fetch that invoice
    try:
        invoice = Invoice.objects.get(slug=slug)
        pass
    except:
        messages.error(request, 'Something went wrong')
        return redirect('invoices')

    #fetch all the products - related to this invoice
    products = Product.objects.filter(invoice=invoice)


    context = {}
    context['invoice'] = invoice
    context['products'] = products

    if request.method == 'GET':
        prod_form  = ProductForm()
        inv_form = InvoiceForm(instance=invoice)
        client_form = ClientSelectForm(initial_client=invoice.client)
        context['prod_form'] = prod_form
        context['inv_form'] = inv_form
        context['client_form'] = client_form
        return render(request, 'invoice/create-invoice.html', context)

    if request.method == 'POST':
        prod_form  = ProductForm(request.POST)
        inv_form = InvoiceForm(request.POST, instance=invoice)
        client_form = ClientSelectForm(request.POST, initial_client=invoice.client, instance=invoice)

        if prod_form.is_valid():
            obj = prod_form.save(commit=False)
            obj.invoice = invoice
            obj.save()

            messages.success(request, "Invoice product added succesfully")
            return redirect('create-build-invoice', slug=slug)
        elif inv_form.is_valid and 'paymentTerms' in request.POST:
            inv_form.save()

            messages.success(request, "Invoice updated succesfully")
            return redirect('create-build-invoice', slug=slug)
        elif client_form.is_valid() and 'client' in request.POST:

            client_form.save()
            messages.success(request, "Client added to invoice succesfully")
            return redirect('create-build-invoice', slug=slug)
        else:
            context['prod_form'] = prod_form
            context['inv_form'] = inv_form
            context['client_form'] = client_form
            messages.error(request,"Problem processing your request")
            return render(request, 'invoice/create-invoice.html', context)


    return render(request, 'invoice/create-invoice.html', context)




def viewPDFInvoice(request, slug):
    #fetch that invoice
    try:
        invoice = Invoice.objects.get(slug=slug)
        pass
    except:
        messages.error(request, 'Something went wrong')
        return redirect('invoices')

    #fetch all the products - related to this invoice
    products = Product.objects.filter(invoice=invoice)

    #Get Client Settings
    p_settings = Settings.objects.get(clientName='MF Pythonista Egypt')

    #Calculate the Invoice Total
    invoiceCurrency = ''
    invoiceTotal = 0.0
    if len(products) > 0:
        for x in products:
            y = float(x.quantity) * float(x.price)
            invoiceTotal += y
            invoiceCurrency = x.currency



    context = {}
    context['invoice'] = invoice
    context['products'] = products
    context['p_settings'] = p_settings
    context['invoiceTotal'] = "{:.2f}".format(invoiceTotal)
    context['invoiceCurrency'] = invoiceCurrency

    return render(request, 'invoice/invoice-template.html', context)



def viewDocumentInvoice(request, slug):
    #fetch that invoice
    try:
        invoice = Invoice.objects.get(slug=slug)
        pass
    except:
        messages.error(request, 'Something went wrong')
        return redirect('invoices')

    #fetch all the products - related to this invoice
    products = Product.objects.filter(invoice=invoice)

    #Get Client Settings
    p_settings = Settings.objects.get(clientName='MF Pythonista Egypt')

    #Calculate the Invoice Total
    invoiceTotal = 0.0
    if len(products) > 0:
        for x in products:
            y = float(x.quantity) * float(x.price)
            invoiceTotal += y



    context = {}
    context['invoice'] = invoice
    context['products'] = products
    context['p_settings'] = p_settings
    context['invoiceTotal'] = "{:.2f}".format(invoiceTotal)

    #The name of your PDF file
    filename = '{}.pdf'.format(invoice.uniqueId)

    #HTML FIle to be converted to PDF - inside your Django directory
    template = get_template('invoice/pdf-template.html')


    #Render the HTML
    html = template.render(context)

    #Options - Very Important [Don't forget this]
    options = {
          'encoding': 'UTF-8',
          'javascript-delay':'10', #Optional
          'enable-local-file-access': None, #To be able to access CSS
          'page-size': 'A4',
          'custom-header' : [
              ('Accept-Encoding', 'gzip')
          ],
      }
      #Javascript delay is optional

    #Remember that location to wkhtmltopdf
    config = pdfkit.configuration(wkhtmltopdf='\\DESKTOP-PD2LU3T\wkhtmltopdf')

    #IF you have CSS to add to template
    css1 = os.path.join(settings.CSS_LOCATION, 'assets', 'css', 'bootstrap.min.css')
    css2 = os.path.join(settings.CSS_LOCATION, 'assets', 'css', 'dashboard.css')

    #Create the file
    file_content = pdfkit.from_string(html, False, configuration=config, options=options)

    #Create the HTTP Response
    response = HttpResponse(file_content, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename = {}'.format(filename)

    #Return
    return response


def emailDocumentInvoice(request, slug):
    #fetch that invoice
    try:
        invoice = Invoice.objects.get(slug=slug)
        pass
    except:
        messages.error(request, 'Something went wrong')
        return redirect('invoices')

    #fetch all the products - related to this invoice
    products = Product.objects.filter(invoice=invoice)

    #Get Client Settings
    p_settings = Settings.objects.get(clientName='MF Pythonista Egypt')

    #Calculate the Invoice Total
    invoiceTotal = 0.0
    if len(products) > 0:
        for x in products:
            y = float(x.quantity) * float(x.price)
            invoiceTotal += y



    context = {}
    context['invoice'] = invoice
    context['products'] = products
    context['p_settings'] = p_settings
    context['invoiceTotal'] = "{:.2f}".format(invoiceTotal)

    #The name of your PDF file
    filename = '{}.pdf'.format(invoice.uniqueId)

    #HTML FIle to be converted to PDF - inside your Django directory
    template = get_template('invoice/pdf-template.html')


    #Render the HTML
    html = template.render(context)

    #Options - Very Important [Don't forget this]
    options = {
          'encoding': 'UTF-8',
          'javascript-delay':'1000', #Optional
          'enable-local-file-access': None, #To be able to access CSS
          'page-size': 'A4',
          'custom-header' : [
              ('Accept-Encoding', 'gzip')
          ],
      }
      #Javascript delay is optional

    #Remember that location to wkhtmltopdf
    config = pdfkit.configuration(wkhtmltopdf='\\DESKTOP-PD2LU3T\wkhtmltopdf')

    #Saving the File
    filepath = os.path.join(settings.MEDIA_ROOT, 'uploads/client_invoices')
    os.makedirs(filepath, exist_ok=True)
    pdf_save_path = filepath+filename
    #Save the PDF
    pdfkit.from_string(html, pdf_save_path, configuration=config, options=options)


    #send the emails to client
    to_email = invoice.client.emailAddress
    from_client = p_settings.clientName
    emailInvoiceClient(to_email, from_client, pdf_save_path)

    invoice.status = 'EMAIL_SENT'
    invoice.save()

    #Email was send, redirect back to view - invoice
    messages.success(request, "Email sent to the client succesfully")
    return redirect('create-build-invoice', slug=slug)



def deleteInvoice(request, slug):
    try:
        Invoice.objects.get(slug=slug).delete()
    except:
        messages.error(request, 'Something went wrong')
        return redirect('invoices')

    return redirect('invoices')


def companySettings(request):
    context = {}
    company = Settings.objects.get(clientName='MF Pythonista Egypt')
    context = {'company': company}
    return render(request, 'invoice/company-settings.html', context)


@login_required
def check_url(request):  
    # Create a Tkinter root window
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    # Get a reference to the active workbook
    active_book = xw.books.active
    # Assign the active workbook to the 'book' variable
    book = active_book
    # Select the active sheet
    sheet = book.sheets.active   
    # Prompt the user to enter the URL using a dialog box
    url = simpledialog.askstring("URL Input", "Enter the URL:")       
    def check_url_with_virustotal(api_key, url):
        # Set up the VirusTotal API endpoint
        api_url = "https://www.virustotal.com/vtapi/v2/url/report"
        # Set up the parameters for the API request
        params = {'apikey': api_key, 'resource': url}
        try:
            # Make the API request
            response = requests.get(api_url, params=params)
            result = response.json()
            # Check if the request was successful
            if response.status_code == 200:
                # Check the scan results
                if result['response_code'] == 1:
                    return f"URL: {url} is safe. Total scans: {result['total']}, positives: {result['positives']}"
                else:
                    return f"URL: {url} is not safe. Reason: {result['verbose_msg']}"
            else:
                return f"Failed to retrieve scan results. Status code: {response.status_code}"
        except requests.exceptions.RequestException as e:
            return f"An error occurred while making the API request: {str(e)}"   
    if not url:
        #print("URL cannot be empty.")
        output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
        sheet.range(output_cell).value = [["URL cannot be empty."]]    
        book.save()
        return   
    if not validators.url(url):
        #print("Invalid URL. Please enter a valid URL.")
        output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
        sheet.range(output_cell).value = [["Invalid URL. Please enter a valid URL."]]    
        book.save()
        return
    # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
    api_key = '01fdee5426e0534bd91f18c3ecf3a1728b5d74874d30a46660a94047a3075af4'
    result = check_url_with_virustotal(api_key, url)   
    output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
    if not output_cell:
        print("Output cell cannot be empty.")
        return   
    sheet.range(output_cell).value = result   
    book.save()   
    context = {
    }
    return render(request, 'invoice\check_url.html', context)

def Open_Ports (request):
    # Create a Tkinter root window
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    # Get a reference to the active workbook
    active_book = xw.books.active
    # Assign the active workbook to the 'book' variable
    book = active_book
    # Select the active sheet
    sheet = book.sheets.active   
    def ping_url(url):
        # Use different ping commands based on the operating system
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", url]
        else:
            cmd = ["ping", "-c", "1", url]
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            return True  # Ping successful
        except subprocess.CalledProcessError:
            return False  # Ping failed
    def check_open_ports(url, ports):
        if not ping_url(url):
            #print (f"The URL {url} is not reachable.")
            output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
            sheet.range(output_cell).value = [[f"The URL {url} is not reachable."]]    
            book.save()
            return
        try:
            # Get IP address from URL
            ip_address = socket.gethostbyname(url)
            #print(f"Checking open ports for {url} ({ip_address}):")
            output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
            sheet.range(output_cell).value = [[f"Checking open ports for {url} ({ip_address}):"]]    
            book.save()
            # Iterate through the specified ports
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                # Attempt to connect to the specified port
                result = sock.connect_ex((ip_address, port))
                # Check if the port is open
                if result == 0:
                    #print(f"Port {port} is open")
                    output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
                    sheet.range(output_cell).value = [[f"Port {port} is open"]]    
                    book.save()                    
                else:
                    #print(f"Port {port} is closed")
                    output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
                    sheet.range(output_cell).value = [[f"Port {port} is closed"]]    
                    book.save()
                sock.close()
        except socket.gaierror:
            #print("Hostname could not be resolved. Please check the URL.")
            output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
            sheet.range(output_cell).value = [["Hostname could not be resolved. Please check the URL."]]    
            book.save()
        except socket.error:
            #print("Couldn't connect to the server.")
            output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
            sheet.range(output_cell).value = [["Couldn't connect to the server."]]    
            book.save()
    # Prompt the user to enter the URL using a dialog box
    url_to_check = simpledialog.askstring("URL Input", "Enter the URL:")    
    ports_to_check = [80, 443, 8080]
    if ping_url(url_to_check):
        #print(f"The URL {url_to_check} is reachable.")
        output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
        sheet.range(output_cell).value = [[f"The URL {url_to_check} is reachable."]]    
        book.save()
        check_open_ports(url_to_check, ports_to_check)
    else:
        #print(f"The URL {url_to_check} is not reachable.")
        output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
        sheet.range(output_cell).value = [[f"The URL {url_to_check} is not reachable."]]    
        book.save()    
    context = {
    }
    return render(request, 'invoice\Open_Ports.html', context)

def Encrypt_Decrypt(request):  
    # Create a Tkinter root window
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    # Get a reference to the active workbook
    active_book = xw.books.active
    # Assign the active workbook to the 'book' variable
    book = active_book
    # Select the active sheet
    sheet = book.sheets.active   
    def vigenere_encrypt(key, cipher):
        alphabet = "abcdefghijklmnopqrstuvwxyz ,."
        # each letter in an alphabet is mapped to its numeric equivalent
        # eg, a:0, b:1, c:2
        message = ""
        key_length = len(key)
        for i, char in enumerate(cipher):
            if char in alphabet:
                key_index = alphabet.index(key[i % key_length])
                char_index = alphabet.index(char)
                encrypted_index = (char_index + key_index) % len(alphabet)
                encrypted_char = alphabet[encrypted_index]
                message += encrypted_char
            else:
                message += char
        return message
    def vigenere_decrypt(messege, key):
        alphabet = "abcdefghijklmnopqrstuvwxyz ,."
        # each letter in an alphabet is mapped to its numeric equivalent
        # eg, a:0, b:1, c:2
        cipher = ""
        key_length = len(key)
        for i, char in enumerate(messege):
            if char in alphabet:
                key_index = alphabet.index(key[i % key_length])
                char_index = alphabet.index(char)
                decrypted_index = (char_index - key_index) % len(alphabet)
                decrypted_char = alphabet[decrypted_index]
                cipher += decrypted_char
            else:
                cipher += char
        return cipher    
    user_input = simpledialog.askstring("Do you want to Encrypt or Decrypt?", "Select enter (e.g., e, d):")   
    if user_input == 'e':
        key = simpledialog.askstring("!! ENCRYPTION MODE IS SELECTED !!", "Please enter key in lower :")
        #print("!! ENCRYPTION MODE IS SELECTED !!")
        #key = input('Enter the key: ').lower()
        plaintext = simpledialog.askstring("!! ENCRYPTION MODE IS SELECTED !!", "Enter the text to encrypt :")
        #plaintext = input('Enter the text to encrypt: ').lower()
        ciphertext = vigenere_encrypt(key, plaintext)
        output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
        sheet.range(output_cell).value = ciphertext   
        book.save()
        #print(f'The encrypted text is: {ciphertext}')
    elif user_input == 'd':
        key = simpledialog.askstring("!! DECRYPTION MODE IS SELECTED !!", "Please enter key in lower :")
        #print("!! DECRYPTION MODE IS SELECTED !!")
        #key = input('Enter the key: ').lower()
        ciphertext = simpledialog.askstring("!! DECRYPTION MODE IS SELECTED !!", "Enter the text to decrypt :")
        #ciphertext = input('Enter the text to decrypt: ').lower()
        plaintext = vigenere_decrypt(ciphertext, key)
        #print(f'The decrypted text is: {plaintext}')
        output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")    
        sheet.range(output_cell).value = plaintext   
        book.save()   
    context = {
    }
    return render(request, 'invoice\Encrypt_Decrypt.html', context)
 
@login_required
def py_sum(request):   
    # Create a Tkinter root window
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    # Get a reference to the active workbook
    active_book = xw.books.active
    # Assign the active workbook to the 'book' variable
    book = active_book
    enter_type = simpledialog.askstring("Select Enter Type", "Select enter type (e.g., name, sub_selected, sub_enter):")
    if enter_type == 'name':
        # Prompt the user to enter the cell address using a dialog box
        selected_name = simpledialog.askstring("Please Enter Value", "Please enter value : ")    
        # Get output cell  
        output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")        
        # Set the values of the selected cell and adjacent cells to the user inputs and result
        sheet = book.sheets.active
        sheet.range(output_cell).value = [['Hello ' + selected_name]]     
        # Save changes to the active workbook
        book.save()
    elif enter_type == 'sub_selected':
        # Get a reference to the active workbook
        active_book = xw.books.active    
        # Assign the active workbook to the 'book' variable
        book = active_book    
        # Prompt the user to enter the cell address using a dialog box
        selected_cell = simpledialog.askstring("Cell Input", "Enter the cell address (e.g., A1):")    
        # Prompt the user to enter the range using a dialog box
        range_input = simpledialog.askstring("Range Input", "Enter the range (e.g., A1:XFD1048576):")        
        # Read the range into a DataFrame
        sheet = book.sheets.active
        df = pd.DataFrame(sheet.range(range_input).value)        
        # Calculate the total
        result = df.sum().item()     
        # Set the value of the selected cell to the result
        selected_range = sheet.range(selected_cell)
        selected_range.value = [[result]]        
        # Save changes to the active workbook
        book.save()              
    elif enter_type == 'sub_enter':
        # Prompt the user to enter the cell address using a dialog box
        selected_cell = simpledialog.askstring("Cell Input", "Enter the cell address (e.g., A1):")
        # Prompt the user to enter three input values using dialog boxes
        value1 = float(simpledialog.askstring("Input 1", "Enter value 1:"))
        value2 = float(simpledialog.askstring("Input 2", "Enter value 2:"))
        value3 = float(simpledialog.askstring("Input 3", "Enter value 3:"))
        value4 = float(simpledialog.askstring("Input 4", "Enter value 4:"))
        value5 = float(simpledialog.askstring("Input 5", "Enter value 5:"))
        value6 = float(simpledialog.askstring("Input 6", "Enter value 6:"))
        value7 = float(simpledialog.askstring("Input 7", "Enter value 7:"))
        value8 = float(simpledialog.askstring("Input 7", "Enter value 8:"))
        # Calculate the result
        result = value1 + value2 + value3 + value4 + value5 + value6 + value7+ value8
        # Select the active sheet
        sheet = book.sheets.active
        # Set the values of the selected cell and adjacent cells to the user inputs and result
        selected_range = sheet.range(selected_cell)
        selected_range.value = [[value1, value2, value3,value4, value5, value6,value7,+ value8, result]]
        # Save changes to the active workbook
        book.save()
    
    context = {
    }
    return render(request, 'invoice\py_sum.html', context)

def py_average(request):
    # Create a Tkinter root window
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    # Get a reference to the active workbook
    active_book = xw.books.active
    # Assign the active workbook to the 'book' variable
    book = active_book
    # Select the active sheet
    sheet = book.sheets.active   
    # Prompt the user to enter the range using a dialog box
    range_input = simpledialog.askstring("Range Input", "Enter the range (e.g., A1:XFD1048576):")
    # Read range as DataFrame  
    df = pd.DataFrame(sheet.range(range_input).value)
    # Calculate average
    result = df.mean().mean()
    # Get output cell  
    output_cell = simpledialog.askstring("Output Cell", "Enter the output cell (e.g. A1):")
    # Set the values of the selected cell and adjacent cells to the user inputs and result
    sheet.range(output_cell).value = [[result]]      
    # Save changes to the active workbook
    book.save()
    
    context = {
        'df': df,  # Pass the processed data to the template
    }

    return render(request, 'invoice\py_average.html', context)

@login_required
def plotting(request):
    # Hide the root window
    root = tk.Tk()
    root.withdraw()
    # Get a reference to the active workbook
    active_book = xw.books.active
    # Assign the active workbook to the 'book' variable
    book = active_book
    # Select the active sheet
    sheet = book.sheets.active
    # Prompt the user to enter the range using a dialog box
    range_input = simpledialog.askstring("Range Input", "Enter the range (e.g., A1:XFD1048576):")
    # Read range as DataFrame
    df = sheet.range(range_input).options(pd.DataFrame).value

    plot_type = simpledialog.askstring("Select Plot Type", "Select plot type (e.g., line, heatmap, scatter, 3d_plot):")
    if plot_type == 'line':
        column_labels = []  # create an empty list for storing column labels 
        while True:  # loop until user stops selecting columns 
            label_input = simpledialog.askstring("Select Column Label", "Select column label (or type 'done' when finished): ")  # ask user for label input 
            if label_input == 'done':  # if user types 'done', break out of loop and move on to next step 
                break   # end of while loop 
            else:   # if user has not typed 'done', add label to list and prompt again for next label input 
                column_labels.append(label_input)
        fig, ax = plt.subplots()
        df[column_labels].plot(ax=ax)
        ax.set_ylabel(simpledialog.askstring("label", "Enter the y-axis label: "))
        ax.set_title(simpledialog.askstring("label", "Enter the plot title: "))
        # Save the figure in the Excel sheet
        sheet.pictures.add(fig, name='Line Plot', update=True)

    elif plot_type == 'heatmap':
        column_labels = []  # create an empty list for storing column labels
        while True:  # loop until user stops selecting columns
            label_input = simpledialog.askstring("Select Column Label", "Select column label (or type 'done' when finished): ")
            if label_input == 'done':
                break
            else:
                column_labels.append(label_input)
        data = {}
        for label in column_labels:
            data[label] = df[label]
        df_heatmap = pd.DataFrame(data)
        sns.heatmap(df_heatmap)
        plt.xlabel('X-axis')
        plt.ylabel('Y-axis')
        plt.title('Heatmap')
        # Save the figure in the Excel sheet
        sheet.pictures.add(plt.gcf(), name='Heatmap', update=True)

    elif plot_type == 'scatter':
        column_labels_input = simpledialog.askstring("Select Column Labels", "Enter column labels separated by commas:")
        column_labels = column_labels_input.split(',')
        plt.figure()
        for label in column_labels:
            plt.scatter(df.index, df[label], label=label)
        plt.xlabel('X-axis')
        plt.ylabel('Y-axis')
        plt.title('Scatter Plot')
        plt.legend()
        # Save the figure in the Excel sheet
        sheet.pictures.add(plt.gcf(), name='Scatter Plot', update=True)
        
    elif plot_type == '3d_plot':
        # Get column labels 
        column_labels_input = simpledialog.askstring("Columns", "Enter columns separated by commas:")
        column_labels = column_labels_input.split(',')      
        # Plot the surface
        fig = plt.figure()
        ax = fig.add_subplot(111, projection='3d')
        for label in column_labels:
            ax.scatter(df.index, df[label], df[label], label=label)
        ax.set_xlabel('X')
        ax.set_ylabel('Y') 
        ax.set_zlabel('Z')
        ax.set_title('3D Scatter Plot')      
        # Save plot
        sheet.pictures.add(ax.get_figure(), name='3D Plot', update=True)
        
    # Save the workbook to reflect the changes
    book.save()
  
    context = {
        'df': df,  # Pass the processed data to the template
    }

    return render(request, 'invoice/plotting.html', context)


def ml_Visua(request):
    # Data processing and visualization code
    bike=pd.read_csv('train.csv')
    bike.info()
    bike.isna().sum()
    bike['datetime']=pd.to_datetime(bike.datetime)
    bike.season.value_counts()
    bike['MonthofYear']=bike.datetime.dt.month
    bike.drop(columns=['registered','casual'],inplace=True)
    
    # Use excelwings to manipulate the excel workbook
    book=xw.books.active
    Sheet=book.sheets('Exploratory Analysis')

    # Creating the plots
    fig,(ax0,ax1,ax2)=plt.subplots(nrows=1,ncols=3)
    fig.set_figheight(6)
    fig.set_figwidth(21)
    sns.boxplot(x='MonthofYear',y='count',data=bike,ax=ax0)
    sns.regplot(x='atemp',y='count',scatter=True,scatter_kws={'alpha':0.05},x_jitter=True,y_jitter=True,data=bike,ax=ax1)
    sns.histplot(x='count',data=bike,ax=ax2)
    ax0.set_title('Bike Rentals by month')
    ax0.set_ylabel('Bike Rentals')
    ax1.set_title('Temp vs Bike rentals')
    ax1.set_ylabel('Bike rentals')
    ax2.set_label('Bike Rentals')
    ax2.set_title('Distribution of Bike Rentals')
    plt.tight_layout()
    sns.set_context('talk')
    #sns.set_theme('dark')
    
    Sheet.pictures.add(fig,name='Bike Rentals',update=True)

    corr_mat=bike.corr().round(2)
    corr_mat
    fig,ax=plt.subplots()
    fig.set_figheight(7)
    fig.set_figwidth(14)
    sns.heatmap(corr_mat,annot=True,linewidth=0.3,cmap='viridis')
    ax.set_title('Correlation Matrix')
    Sheet.pictures.add(fig,name='Corr_mat',update=True,left=Sheet.range('B37').left,top=Sheet.range('B37').top)
    X=bike[['atemp','MonthofYear','humidity','weather','holiday']]
    y=bike['count']
    bike.holiday.value_counts()
    y

    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2)
    max_depths=[3,4,5,6,7,8,9,10,11,12,13,14,15]
    for max_depth in max_depths:
        dt=DecisionTreeRegressor(max_depth=max_depth,random_state=20)
        dt.fit(X_train,y_train)
        y_pred=dt.predict(X_test)
        score=r2_score(y_test,y_pred)
        #print('The r2_score of tree with max depth {} is'.format(max_depth),score)
    
    dt=DecisionTreeRegressor(max_depth=4)
    dt.fit(X_train,y_train)
    y_pred=dt.predict(X_test)
    sheet2=book.sheets('Decision tree')

    # Assuming you have an Index object named 'feature_names'
    feature_names = pd.Index(['atemp', 'MonthofYear', 'humidity', 'weather', 'holiday'])

    # Convert the Index object to a list
    feature_names_list = feature_names.tolist()

    # Create and fit the decision tree model
    model = tree.DecisionTreeClassifier()
    model.fit(X, y)

    fig,ax=plt.subplots()
    fig.set_figheight(35)
    fig.set_figwidth(35)
    _=tree.plot_tree(dt,feature_names=feature_names_list,filled=True)
    sheet2.pictures.add(fig,name='Tree',update=True,left=sheet2.range('A6').left,top=sheet2.range('A6').left)
    type(fig)

    dt=DecisionTreeRegressor(max_depth=7)
    dt.fit(X_train,y_train)
    y_pred=dt.predict(X_test)
    sheet2.range('B2').value=dt.max_depth
    sheet2.range('B3').value=r2_score(y_test,y_pred).round(2)

    #Now trying Random forest
    #We will probably not know the number of registered users ahead of time so drop the columns casual and registered to make this problem interestins
    #We can use random forest to get feature importances and use it as a dimensionality reduction technique

    #bike.drop(columns=['registered','casual'],inplace=True)
    X=bike.drop(columns=['count','datetime'])
    X.info()
    y=bike['count']
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2)
    X_train

    for max_depth in max_depths:
        rf=RandomForestRegressor(n_estimators=100,max_depth=max_depth,random_state=30)
        rf.fit(X_train,y_train)
        y_pred=rf.predict(X_test)
        score=r2_score(y_test,y_pred)
        #print('R2_score with {} max depth is'.format(max_depth),score)
    
    rf=RandomForestRegressor(n_estimators=100,max_depth=11,random_state=30)
    rf.fit(X_train,y_train)
    y_pred=rf.predict(X_test)
    score=r2_score(y_test,y_pred)
    sheet3=book.sheets('Random forest')
    sheet3.range('B4').value=score.round(2)
    sheet3.range('B2').value=rf.n_estimators
    sheet3.range('B3').value=rf.max_depth

    mat=pd.DataFrame(rf.feature_importances_,index=X.columns).sort_values(by=[0])
    fig,ax=plt.subplots()
    fig.set_figheight(7)
    fig.set_figwidth(12)
    ax.barh(width=mat[0],y=mat.index)
    plt.xticks(rotation=45)
    ax.set_title('Feature Importances')
    sheet3.pictures.add(fig,name='Feature',update=True,left=sheet3.range('A8').left,top=sheet3.range('A8').left)
    type(mat)

    context = {
        'bike': bike,  # Pass the processed data to the template
    }

    return render(request, 'invoice\ml_Visua.html', context)