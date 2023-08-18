import re
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.edge.service import Service
from bs4 import BeautifulSoup


url = "https://www.securitylab.ru/_services/export/rss/"
date_input = "14.08.2023"
service = Service(r'msedgedriver.exe')
options = webdriver.EdgeOptions()

options.add_argument("--disable-blink-features=AutomationControlled")
options.add_argument("--disable-infobars")
options.add_argument("--start-maximized")
options.add_argument("--ignore-certificate-errors")
# options.add_argument("--headless")

driver = webdriver.Edge(options=options, service=service)

driver.get(url)
html = driver.page_source
soup = BeautifulSoup(html, "xml")

items = soup.find_all("item")
all_links = []
all_dates = []
all_title = []
for item in items:
    tit = item.title.text
    links = item.link.text
    dates_pars = item.pubDate.text
    buffer_date = []
    for i in range(5, 16):
        buffer_date.append(dates_pars[i])

    date = ''.join(buffer_date)
    date = re.sub(" Jan ", ".01.", date)
    date = re.sub(" Feb ", ".02.", date)
    date = re.sub(" Mar ", ".03.", date)
    date = re.sub(" Apr ", ".04.", date)
    date = re.sub(" May ", ".05.", date)
    date = re.sub(" Jun ", ".06.", date)
    date = re.sub(" Jul ", ".07.", date)
    date = re.sub(" Aug ", ".08.", date)
    date = re.sub(" Sep ", ".09.", date)
    date = re.sub(" Oct ", ".10.", date)
    date = re.sub(" Nov ", ".11.", date)
    date = re.sub(" Dec ", ".12.", date)
    print(date)
    #date_input = datetime.strptime(date_input, "%d.%m.%Y")
    #dates = datetime.strptime(date, "%d.%m.%Y")

    all_dates.append(date)
    all_links.append(links)
    all_title.append(tit)

print(all_dates)
print(all_links)
print(all_title)
for i in range(len(all_links)):
    driver.get(all_links[i])
    get_source = driver.page_source
    search_text = "CVE"
    CVE = search_text in get_source
    if CVE:
        print(all_links[i])
driver.close()
