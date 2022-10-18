
#====================================== Loading required libraries ================================================
import tkinter
from tkinter import *
from PIL import ImageTk, Image
import re
import requests
import builtwith
import whois
# import csv
import pandas as pd
import sublist3r
import errno
import os
import openpyxl
from bs4 import BeautifulSoup
import time
import pyautogui
from selenium import webdriver
from selenium.webdriver import ActionChains
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager

#====================================== Chrome Webdriver Initialization ===========================================

def initializeDriver():

    ### Initialize Driver for all search engines here !!
    options = webdriver.ChromeOptions()
    options.add_experimental_option("excludeSwitches", ["ignore-certificate-errors"])
    options.add_experimental_option("useAutomationExtension", True)
    options.add_extension('1.0_0.crx')
    # options.add_argument('--disable-gpu')
    # options.add_argument('--headless') # to hide the browser

    # ChromeDriverManager helps you avoid below error
    """
    selenium.common.exceptions.SessionNotCreatedException: Message: session not created: This version of ChromeDriver only supports Chrome version 80
    """
    return webdriver.Chrome(ChromeDriverManager().install(),options=options)

driver = initializeDriver()
action = ActionChains(driver)

#================================== Function to fetch domain registration details ==================================

def whois_fetch(domain):
    w = whois.whois(domain)
    domain_whois = []
    temprecord = {}
    temprecord['Domain'] = w.domain
    if isinstance(w.expiration_date, list):
        for i, date in enumerate(w.expiration_date):
            temprecord[f'ExpiryDate_{i + 1}'] = date
    else:
        temprecord['ExpiryDate'] = w.expiration_date
    if isinstance(w.name_servers, list):
        for i, ns in enumerate(w.name_servers):
            temprecord[f'NameServer_{i + 1}'] = ns
    else:
        temprecord['NameServer'] = w.name_servers
    if isinstance(w.emails, list):
        for i, mails in enumerate(w.emails):
            temprecord[f'Emails_{i + 1}'] = mails
    else:
        temprecord['Emails'] = w.emails
    if isinstance(w.address, list):
        temprecord['Address'] = w.address[1]
    else:
        temprecord['Address'] = w.address
    temprecord['City'] = w.city
    temprecord['ZIP'] = w.zipcode
    temprecord['Country'] = w.country
    domain_whois.append(temprecord)
    result = []
    for key, value in domain_whois[0].items():
        result.append(f'{key} : {value}')

    return result

#================================= Function to fetch web technologies used on domain  =============================

def Webtechno(domain):
    time.sleep(2)
    url = 'https://' + domain
    response = requests.get(url)
    r = response.headers
    tech_used = builtwith.parse(url)
    df1 = pd.DataFrame(list(tech_used.items()))
    df2 = pd.DataFrame(list(r.items()))
    df = pd.concat([df1, df2])
    result1 = df1.values.tolist()
    result2 = df2.values.tolist()
    fullresult = result1 + result2

    return fullresult

#======================== Function to generate subdomains and related open ports ==================================

def subDomain_Function(domain):
    time.sleep(3)
    subdomains, open_ports = sublist3r.main(domain, 40, 'subdomain.txt', ports='20,21,22,23,25,69,137,139,445,53', silent=False, verbose=True,
                                            enable_bruteforce=False, engines=None)
    subDomains_List = []
    for port in open_ports:
        tempRecord = {}
        tempRecord['subdomain'] = port.split(':')[0]
        tempRecord['ports'] = port.split(':')[1]
        subDomains_List.append(tempRecord)

    return subDomains_List

#========================== Function to generate emails and check breach status =================

def get_domain_Emails(domain):
        global driver
        driver.get('https://hunter.io/search')
        username = driver.find_element(by=By.XPATH, value='//*[@id="email-field"]')
        username.click()
        username.send_keys('****@gmail.com')
        time.sleep(2)
        password = driver.find_element(by=By.XPATH, value='//*[@id="password-field"]')
        password.click()
        password.send_keys('*******')
        time.sleep(2)
        signin = driver.find_element(by=By.XPATH, value='//*[@id="signin_form"]/div[2]/button[2]')
        signin.click()
        time.sleep(5)
        search = driver.find_element(by=By.XPATH, value='//*[@id="domain-field"]')
        search.click()
        search.send_keys(domain)
        domainsearchclick = driver.find_element(by=By.XPATH, value='//*[@id="search-btn"]')
        domainsearchclick.click()
        time.sleep(5)
        export = driver.find_element(by=By.XPATH, value='//*[@id="download-link-premium"]')
        export.click()
        from bs4 import BeautifulSoup
        pagecontent = driver.page_source
        soup = BeautifulSoup(pagecontent, 'html.parser')
        results = soup.findAll('div', class_='email')
        # len(results)
        emails = []
        for result in results:
            emails.append(result.text)
        return emails

def check_Email_Breaches(email):
        time.sleep(2)
        search = driver.find_element(by=By.XPATH, value='//*[@id="home"]/div/form/div/input')
        action = ActionChains(driver)
        search.clear()
        search.click()
        search.send_keys(f'{email}\n')
        time.sleep(5)

        from bs4 import BeautifulSoup
        pagecontent = driver.page_source
        soup = BeautifulSoup(pagecontent, 'html.parser')
        cards = soup.findAll('div', class_='card')
        breaches = []
        for card in cards:
            try:
                line1 = card.find('a').get('href')
                print(line1)
                line2 = card.find('a').text
                print(line2)
            except:
                line1 = ''
                line2 = ''
            try:
                line3 = card.find('a').next_sibling.text
                print(line3)
            except:
                line3 = ''
            result = line1 + '\n' + line2 + '\n' + line3
            breaches.append(result)

        result = []
        for breach in breaches: # check if breach is a list or not
            if isinstance(breach, list) and isinstance(breach[0],dict):
                for key, value in breach.items():
                    result.append(f'{key} : {value}')
            else:
                result.append(breach)

        return result

def get_EmailBreaches(domain):

        domainEmails = get_domain_Emails(domain)
        driver.get('https://breachdirectory.org/')
        breaches_list = []
        for email in domainEmails:
            time.sleep(3)
            temp_dict = {}
            temp_dict[email] = '\n'.join(check_Email_Breaches(email))
            breaches_list.append(temp_dict)

        master_list = []
        for breaches in breaches_list:
            temp_dict = {}
            for key, value in breaches.items():
                temp_dict['email'] = key
                temp_dict['breaches'] = value.strip()
                master_list.append(temp_dict)

        return master_list

#==================== Function to generate Metadata documents hosted on the domain  ===============================

def get_metaDataDocs(domain):
    global driver
    chrome_options = Options()
    driver.maximize_window()
    url = 'https://' + domain
    driver.get(url)
    pyautogui.moveTo(1777, 64, duration=1)
    pyautogui.click(1777, 64)
    time.sleep(1)
    pyautogui.moveTo(1539, 242, duration=1)
    pyautogui.click(1539, 242)
    time.sleep(1)
    pyautogui.moveTo(852, 164, duration=1)
    pyautogui.click(852, 164)
    time.sleep(5)
    # to save the results to a file
    pyautogui.moveTo(855, 193, duration=1)
    pyautogui.click(855, 193)

#===== Logic to return a response after check for any documents on the domain =====================================

    if os.path.exists('C:/Users/dream/Downloads/' + domain + '.txt'):
        print('File downloaded')
        # get a list of all the links of the pdf from the downloaded file
        with open('C:/Users/dream/Downloads/' + domain + '.txt', 'r') as f:
            lines = f.readlines()
            links = [f'Documents links have been saved to {domain}.txt']
            for line in lines:
                if 'https' in line:
                    links.append(line)
            return links
    else:
        print('File not downloaded')
        return 'No Files to get Meta data from for this domain'

#======================== Function for checkbox selections for desired result =====================================

def selecDeselct():
    global check_box_list
    # to select all checkboxes
    if select_deselectAll_chBox.get() == 1:
        for i in check_box_list:
            i.set(True)
    else:
        for i in check_box_list:
            i.set(False)

#======= To get & pass domain name,check domain validity,trigger code as per selection & rename report as per domain

def master_Function():
    global check_box_list , master_data
    clear_Output()
    master_data.clear()

    domainName = whois_text.get()
    # check for domain name validity
    # regex to check for valid domain name
    regex = re.compile(r'^(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$')
    if regex.match(domainName):
        print('Domain name is valid')
    else:
        print('Domain name is invalid')
        output_list.insert(END, 'Domain name is invalid')
        return 'Domain name is invalid'

#============ To trigger code execution as per checkbox selection =================================================

    for i in range(len(check_box_list)):
        if check_box_list[i].get() == 1  and check_box_list[i]._name == 'whoIs':
            Domreg_list = whois_fetch(whois_text.get())
            master_data.append("================= Domain Registration Details =================")
            master_data.extend(Domreg_list)

            if Download_chBox.get() == 1:
                exists = os.path.isfile(f'{domainName}.xlsx')
                Domreg_listpr = pd.DataFrame(Domreg_list)
                if not exists:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='w') as writer:
                        Domreg_listpr.to_excel(writer, sheet_name='Dom Reg Details', header=False,index=False)
                else:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
                        Domreg_listpr.to_excel(writer, sheet_name='Dom Reg Details', header=False,index=False)

        if check_box_list[i].get() == 1 and check_box_list[i]._name == 'subDomain':
            time.sleep(5)
            subDomain_list = subDomain_Function(whois_text.get())
            newsublist = []
            for d in subDomain_list:
                tempdict = {}
                tempdict = (f"{d['subdomain']} : {d['ports']}")
                newsublist.append(tempdict)
            master_data.append("=================  SubDomains & Ports Details =================")
            master_data.extend(newsublist)

            if Download_chBox.get() == 1:
                exists = os.path.isfile(f'{domainName}.xlsx')
                subDomain_listpr = pd.DataFrame(subDomain_list)
                if not exists:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='w') as writer:
                        subDomain_listpr.to_excel(writer, sheet_name='Subdomains and Ports', header=False,index=False)
                else:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
                        subDomain_listpr.to_excel(writer, sheet_name='Subdomains and Ports', header=False,index=False)

        if check_box_list[i].get() == 1 and check_box_list[i]._name == 'webTechnologies':
            webTechnoList = Webtechno(whois_text.get())
            master_data.append("================= Web Technologies used on Domain =================")
            master_data.extend(webTechnoList)

            if Download_chBox.get() == 1:
                exists = os.path.isfile(f'{domainName}.xlsx')
                webTechnoListpr = pd.DataFrame(webTechnoList)
                if not exists:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='w') as writer:
                        webTechnoListpr.to_excel(writer, sheet_name='Domain Technologies', header=False, index=False)
                else:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
                        webTechnoListpr.to_excel(writer, sheet_name='Domain Technologies', header=False, index=False)

        if check_box_list[i].get() == 1 and check_box_list[i]._name == 'emailBreaches':
            emailBreaches_list = get_EmailBreaches(whois_text.get())
            newebsublist = []
            for d in emailBreaches_list:
                tempdict = {}
                tempdict = (f"{d['email']} : {d['breaches']}")
                newebsublist.append(tempdict)
            master_data.append("================= Emails breach check for Domain =================")
            master_data.extend(newebsublist)

            if Download_chBox.get() == 1:
                exists = os.path.isfile(f'{domainName}.xlsx')
                emailBreachespr = pd.DataFrame(emailBreaches_list)
                if not exists:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='w') as writer:
                        emailBreachespr.to_excel(writer, sheet_name='Email Breaches', header=False, index=False)
                else:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
                        emailBreachespr.to_excel(writer, sheet_name='Email Breaches', header=False, index=False)

        if check_box_list[i].get() == 1 and check_box_list[i]._name == 'metaDataDocs':
            metaDataDocslist = get_metaDataDocs(whois_text.get())
            master_data.append("================= Metadata Documents on Domain =================")
            master_data.extend(metaDataDocslist)
            if Download_chBox.get() == 1:
                exists = os.path.isfile(f'{domainName}.xlsx')
                metaDataDocspr = pd.DataFrame(metaDataDocslist)
                if not exists:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='w') as writer:
                        metaDataDocspr.to_excel(writer, sheet_name='MetaData Documents', header=False, index=False)
                else:
                    with pd.ExcelWriter(f'{domainName}.xlsx', engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
                        metaDataDocspr.to_excel(writer, sheet_name='MetaData Documents', header=False, index=True)

    output_list.delete(0,END) # ======== to write the data to the output box on the app window
    for dataLine in master_data:
        output_list.insert(END,dataLine) # ======== to write the data to the output box on the app window

#======== Function to clear the output data on the app window  ====================================================

def clear_Output():
    output_list.delete(0,END)

master_data = [] # master list that can contains all the returned data from all the functions

def clear_Domain():
    whois_entry.delete(0, END)
#=============== Main Application for App window and functionality ================================================

app = Tk()

#===== Domain name label name,attributes,input and position details ===============================

whois_text = StringVar()
part_label = Label(app, bg='#dfe3ee', text='Domain Name', font=('bold', 12), pady=20, padx=20)
part_label.grid(row=0, column=0, sticky=W)
whois_entry = Entry(app, textvariable=whois_text)
whois_entry.grid(row=0, column=1)

#===== Binding/Invoking the enter button on keyboard to the submit button on App ==================
whois_entry.bind('<Return>', lambda event=None: fetch_btn.invoke())

# ===== Checkboxes for all options  on App window ==================================================

whoIS_chBox = IntVar(value=1, name='whoIs')
Checkbutton(app, text='Domain Reg Details', variable=whoIS_chBox,onvalue = 1, offvalue = 0, height = 3, width = 20,anchor='w',bg='#dfe3ee',font=('bold', 12), ).grid(row=1, column=0, padx = 20, pady = 0, sticky=W)

webTechnologies_chBox = IntVar(value=1, name='webTechnologies')
Checkbutton(app, text='Web Technologies', variable=webTechnologies_chBox,onvalue = 1, offvalue = 0, height = 3, width = 20,anchor='w',bg='#dfe3ee',font=('bold', 12)).grid(row=2, column=0,padx = 20, pady = 0, sticky=W)

Download_chBox = IntVar(value=1, name='Download')
Checkbutton(app, text='Download Result', variable=Download_chBox,onvalue = 1, offvalue = 0, height = 3, width = 20,anchor='w',bg='#dfe3ee',font=('bold', 12)).grid(row=0, column=2,padx = 20, pady = 0, sticky=W)

subDomain_chBox = IntVar(value=1, name='subDomain')
Checkbutton(app, text='Sub-Domains & Ports', variable=subDomain_chBox,onvalue = 1, offvalue = 0, height = 3, width = 20,anchor='w',bg='#dfe3ee',font=('bold', 12), ).grid(row=1, column=1)

emailBreach_chBox = IntVar(value=1, name='emailBreaches')
Checkbutton(app, text='Email Breaches', variable=emailBreach_chBox,onvalue = 1, offvalue = 0, height = 3, width = 20,anchor='w', bg='#dfe3ee',font=('bold', 12)).grid(row=2, column=1)

metaDataDocs_chBox = IntVar(value=1, name='metaDataDocs')
Checkbutton(app, text='Metadata Documents', variable=metaDataDocs_chBox,onvalue = 1, offvalue = 0, height = 3, width = 20,anchor='w',bg='#dfe3ee',font=('bold', 12)).grid(row=1, column=2)

#===== List of checkbox variables that referenced for "If" condition on line   above  ==================
check_box_list = [whoIS_chBox, subDomain_chBox, webTechnologies_chBox, emailBreach_chBox, metaDataDocs_chBox]

#=== Checkbox option for selecting/Deselecting all checkbox, used in "If" condition on line   above  ============
select_deselectAll_chBox = IntVar(value=1)
Checkbutton(app, text='Select/Deselect All', variable=select_deselectAll_chBox,onvalue = 1, offvalue = 0, height = 3, width = 20,anchor='w',bg='#dfe3ee',font=('bold', 12), command=selecDeselct).grid(row=2, column=2)

#========  Attributes of the output box on the app window =========================================

output_list = Listbox(app, height=20, width=100, border=6)
output_list.grid(row=20, column=0, columnspan=3, rowspan=6, sticky=E, pady=5)

#========  Placing the scroll bar on the app window ===============================================
scrollbar = Scrollbar(app, orient=VERTICAL)
scrollbar.grid(row=20, column =3, rowspan=6, sticky=(W+N+S), pady=5)

#========  Configuring the scroll bar to attach to the output window  =============================

output_list.configure(yscrollcommand=scrollbar.set)
scrollbar.configure(command=output_list.yview)

#========  Submit,Clear and Exit Buttons on the App window  =======================================

fetch_btn = Button(app, bg='#cd8de5', text='Submit',font=('bold', 11), width=12, command= master_Function)
fetch_btn.grid(row=3, column=1, padx=0, pady=5)

clear_btn = Button(app, bg='#cd8de5', text='Clear',font=('bold', 11), width=12, command=lambda: [clear_Output(), clear_Domain()])
clear_btn.grid(row=4, column=1, padx=0, pady=5)

quit_btn = Button(app, bg='#cd8de5', text='Exit',font=('bold', 11), width=12, command=app.quit)
quit_btn.grid(row=50, column=1, padx=0, pady=15)

#========  Attributes of the App window look  =====================================================

app.title('RGU OSINT Tool©️')
# app.geometry('880x850') # this is without side logo portion
app.geometry('1100x850')
app.configure(bg='#dfe3ee')
app.iconbitmap('C:/Users/dream/PycharmProjects/virenpythonproject/Projectfiles/RGU.ico')

load= Image.open("C:/Users/dream/PycharmProjects/virenpythonproject/Projectfiles/unicornupd3.png")
render = ImageTk.PhotoImage(load)
img = Label(app, image=render, bg='#dfe3ee')
img.place(x=865, y=25)

app.mainloop() # Completes the App window loop or program loop for completion/loading





