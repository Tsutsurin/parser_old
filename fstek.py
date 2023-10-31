from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
from bs4 import BeautifulSoup
from datetime import date
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
all_problem_product = []
all_problem_url = []
all_problem_cve_edited = []
all_problem_cvss_edited = []

num_pages = int(input("Склько страниц ФСТЭКа нужно просмотреть? "))

for page in range(1, num_pages + 1):
    url = ("https://bdu.fstec.ru/vul?sort=identifier&page={}".format(page))
    driver.get(url)
    html = driver.page_source
    soup = BeautifulSoup(html, "lxml")

    tds = soup.find_all("td", class_="col-lg-3 col-xs-3")
    for td in tds:
        links = td.find_all("a", class_="confirm-vul")
        for link in links:
            href = link["href"]
            vul_link = ("https://bdu.fstec.ru{}".format(href))
            print("Уязвимость по ссылке {} найдена".format(vul_link))
            all_problem_url.append(vul_link)

for vul_link in all_problem_url:
    driver.get(vul_link)
    html = driver.page_source
    soup = BeautifulSoup(html, "lxml")

    tds = soup.find_all("td")
    problem_product = tds[3].text.strip() + " " + tds[5].text.strip()
    all_problem_product.append(problem_product)

    cvss = tds[23].text.strip()
    pattern = r"\d+(?:,\d+)?"
    number = re.findall(pattern, cvss)
    size = len(number) - 1
    if any(map(str.isnumeric, cvss)):
        problem_cvss = number[size].replace(',', '.')
        all_problem_cvss.append(problem_cvss)

    cve = tds[39].text.strip()
    pattern = r"CVE: "
    problem_cve = re.sub(pattern, "", cve)
    all_problem_cve.append(problem_cve)

    source.append("ФСТЭК")

    all_problem_data.append(tds[19].text.strip())

driver.close()

for cve in all_problem_cve:
    cve = cve.replace("\u00a0", " ")
    matches = re.findall("CVE-\d{4}-\d{4,}", cve)
    if matches:
        match = matches[0]
        all_problem_cve_edited.append(match)
    else:
        all_problem_cve_edited.append("Zero-day")

for j in range(len(all_problem_cvss)):
    pattern = r"\d+(?:.\d+)?"
    number = re.findall(pattern, all_problem_cvss[j])
    if len(number) == 1:
        if float(number[0]) < 4:
            all_problem_cvss[j] = f"{number[0]} Low"
        elif float(number[0]) < 7:
            all_problem_cvss[j] = f"{number[0]} Medium"
        elif float(number[0]) < 9:
            all_problem_cvss[j] = f"{number[0]} High"
        else:
            all_problem_cvss[j] = f"{number[0]} Critical"
    else:
        all_problem_cvss[j] = "-"
    all_problem_cvss_edited.append(all_problem_cvss[j])

check = len(all_problem_url)
while len(source) != check:
    source.append("-")
while len(all_problem_data) != check:
    all_problem_data.append("-")
while len(all_problem_cve_edited) != check:
    all_problem_cvss_edited.append("-")
while len(all_problem_product) != check:
    all_problem_product.append("-")

df = pd.DataFrame({"Источник": source,
                   "Дата публикации": all_problem_data,
                   "CVE": all_problem_cve_edited,
                   "CVSS": all_problem_cvss_edited,
                   "Продукт": all_problem_product,
                   "Ссылка": all_problem_url})

today = date.today()
today = today.strftime('%d-%m-%Y') + " ФСТЭК"
with pd.ExcelWriter("{}.xlsx".format(str(today))) as writer:
    df.to_excel(writer, sheet_name='ФСТЭК', index=False)
    print("Ежедневный отчет {}.xlsx создан".format(str(today)))
