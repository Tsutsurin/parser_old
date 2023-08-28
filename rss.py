import re
import pandas as pd
from datetime import datetime as dt
from selenium import webdriver
from selenium.webdriver.edge.service import Service
from bs4 import BeautifulSoup

with open ('utilities/rss.txt', 'r') as f:
    lines = [line.rstrip() for line in f]

date_input = input("По какую дату искать новости? ")
date_input = dt.strptime(date_input, '%d.%m.%Y')

service = Service(r'utilities/msedgedriver.exe')
options = webdriver.EdgeOptions()

options.add_argument("--disable-blink-features=AutomationControlled")
options.add_argument("--disable-infobars")
options.add_argument("--start-maximized")
options.add_argument("--ignore-certificate-errors")
options.add_argument("--log-level=3")
# options.add_argument("--headless")

driver = webdriver.Edge(options=options, service=service)

all_links = []
all_dates = []
all_title = []

print(lines)
for url in lines:
    driver.get(url)
    html = driver.page_source
    soup = BeautifulSoup(html, "xml")

    items = soup.find_all("item")

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

        time_date = dt.strptime(date, '%d.%m.%Y')
        if time_date > date_input:
            all_dates.append(date)
            all_links.append(links)
            all_title.append(tit)

counter = []
for i in range(len(all_links)):
    driver.get(all_links[i])
    get_source = driver.page_source
    search_text = "CVE-"
    cve = search_text in get_source
    if cve:
        print(all_links[i])
        counter.append(i)

driver.close()

counter_title = []
counter_links = []
counter_dates = []

for i in range(len(all_links)):
    if i == counter:
        counter_title.append([i])
        counter_links.append([i])
        counter_dates.append([i])

df = pd.DataFrame({"Заголовок": counter_title,
                   "Ссылка": counter_links,
                   "Дата": counter_dates})

with pd.ExcelWriter("новости.xlsx") as writer:
    df.to_excel(writer, sheet_name='Проблемы', index=False)
    print("Таблица новости.xlsx создана")
