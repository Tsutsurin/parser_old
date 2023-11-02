from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
from bs4 import BeautifulSoup
import time
from datetime import date
from datetime import datetime
import pandas as pd
import re

service = Service(r'utilities/msedgedriver.exe')
options = Options()
options.add_argument("disable-blink-features=AutomationControlled")
options.add_argument("disable-infobars")
options.add_argument("start-maximized")
options.add_argument("ignore-certificate-errors")
options.add_argument("log-level=3")
driver = webdriver.Edge(options=options, service=service)

all_problem_url = []
all_problem_data = []
all_description = []
source = []

with open ('utilities/rss.txt', 'r') as f:
    lines = [line.rstrip() for line in f]

for url in lines:
    driver.get(url)
    time.sleep(5)
    html = driver.page_source
    soup = BeautifulSoup(html, "html.parser")
    items = soup.find_all("item")
    for item in items:
        description = item.find("description").text
        if ("уязвим" in description) or ("CVE" in description):
            all_description.append(description)

            source.append(url)

            link_tg = item.find("link")
            all_problem_url.append(link_tg.next_sibling)
            print(link_tg.next_sibling)

            date_time_str = item.find("pubdate").text
            try:
                date_time_obj = datetime.strptime(date_time_str, "%a, %d %b %Y %X %z")
                date_edited = date_time_obj.date()
                all_problem_data.append(date_edited.strftime("%d.%m.%Y"))
            except:
                all_problem_data.append(date_time_str)

driver.close()

check = len(all_problem_url)
while len(source) != check:
    source.append("-")
while len(all_problem_data) != check:
    all_problem_data.append("-")
while len(all_description) != check:
    all_description.append("-")

df = pd.DataFrame({"Источник": source,
                   "Дата публикации": all_problem_data,
                   "Описание": all_description,
                   "Ссылка": all_problem_url})

today = date.today()
today = today.strftime('%d-%m-%Y') + " RSS"
with pd.ExcelWriter("{}.xlsx".format(str(today))) as writer:
    df.to_excel(writer, sheet_name='RSS', index=False)
    print("Ежедневный отчет {}.xlsx создан".format(str(today)))
