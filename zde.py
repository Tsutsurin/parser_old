from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
from bs4 import BeautifulSoup
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

source = []
all_problem_data = []
all_problem_cve = []
all_problem_cvss = []
all_problem_url = []
all_problem_product = []

url = ("https://www.zerodayinitiative.com/rss/published/2023/")
driver.get(url)
html = driver.page_source
soup = BeautifulSoup(html, "html.parser")
items = soup.find_all("item")
for item in items:
    source.append(item.find("guid").text)
    date_time_str = item.find("pubdate").text
    date_time_obj = datetime.strptime(date_time_str, "%a, %d %b %Y %X %z")
    date_edited = date_time_obj.date()
    all_problem_data.append(date_edited.strftime("%d.%m.%Y"))

    link_tg = item.find("link")
    all_problem_url.append(link_tg.next_sibling)

    title = item.find("title").text
    start = title.find(":") + 1
    end = len(title) - 1
    all_problem_product.append(title[start:end])

    description = item.find("description").text
    matches = re.findall("CVE-\d{4}-\d{4,}", description)
    if matches:
        match = matches[0]
        all_problem_cve.append(match)
    else:
        all_problem_cve.append("zero-day")

    if "CVSS rating" in description:
        rating =  re.search(r"\d+\.\d+", description).group()
        all_problem_cvss.append(rating)

driver.close()

check = len(all_problem_url)
while len(source) != check:
    source.append("-")
while len(all_problem_data) != check:
    all_problem_data.append("-")
while len(all_problem_cve) != check:
    all_problem_cvss.append("-")
while len(all_problem_product) != check:
    all_problem_product.append("-")

df = pd.DataFrame({"Источник": source,
                   "Дата публикации": all_problem_data,
                   "CVE": all_problem_cve,
                   "CVSS": all_problem_cvss,
                   "Продукт": all_problem_product,
                   "Ссылка": all_problem_url})

today = date.today()
today = today.strftime("%d-%m-%Y") + " ZDE"
with pd.ExcelWriter("{}.xlsx".format(str(today))) as writer:
    df.to_excel(writer, sheet_name='ZDE', index=False)
    print("Ежедневный отчет {}.xlsx создан".format(str(today)))