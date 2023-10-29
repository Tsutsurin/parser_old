from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
from bs4 import BeautifulSoup
from datetime import date
import time
import pandas as pd
import re

service = Service(r'msedgedriver.exe')
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

num_pages = int(input("Склько страниц НКЦКИ нужно просмотреть? "))

for page in range(1, num_pages + 1):
    url = ("https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1={}".format(page))
    time.sleep(5)
    driver.get(url)
    html = driver.page_source
    soup = BeautifulSoup(html, "lxml")

    problem_links = [elem.get("href") for elem in soup.find_all("a", title="Подробнее")]

    problem_url = ["https://safe-surf.ru" + link for link in problem_links]

    for _ in range(len(problem_url)):
        print("Уязвимость по ссылке {} найдена".format(problem_url[_]))

    problem_data = [elem.get_text().strip().replace("Дата бюллетеня", "") for elem in
                    soup.find_all(class_="cell-bulletin-nkcki cell-1")]
    problem_data = list(filter(bool, problem_data))
    problem_data = [elem.lstrip() for elem in problem_data]

    problem_cve = [elem.get_text().strip().replace("Идентификатор уязвимости", "") for elem in
                   soup.find_all(class_="cell-bulletin-nkcki cell-2")]
    problem_cve = list(filter(bool, problem_cve))
    problem_cve = [elem.lstrip() for elem in problem_cve]
    problem_cve = [elem.strip().replace("MITRE:", "") for elem in problem_cve]

    problem_product = [elem.get_text().strip().replace("Уязвимый продукт", "") for elem in
                       soup.find_all(class_="cell-bulletin-nkcki cell-3")]
    problem_product = list(filter(bool, problem_product))
    problem_product = [elem.lstrip() for elem in problem_product]
    problem_product = [elem.replace("\n", "") for elem in problem_product]
    problem_product = [re.sub(
        "                                                                                                                                 ",
        "     ", elem) for elem in problem_product]

    problem_cvss = [elem.get_text().strip().replace("Уровень опасности", "") for elem in
                    soup.find_all(class_="cell-bulletin-nkcki cell-4")]
    problem_cvss = list(filter(bool, problem_cvss))
    problem_cvss = [elem.lstrip() for elem in problem_cvss]
    problem_cvss = [elem.replace("\n", "") for elem in problem_cvss]
    problem_cvss = [re.sub("\\s+", " ", elem) for elem in problem_cvss]

    all_problem_cve.extend(problem_cve)
    all_problem_cvss.extend(problem_cvss)
    all_problem_data.extend(problem_data)
    all_problem_product.extend(problem_product)
    all_problem_url.extend(problem_url)
    for i in range(len(problem_url)):
        source.append("НКЦКИ")

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
today = today.strftime('%d-%m-%Y') + " НКЦКИ"
with pd.ExcelWriter("{}.xlsx".format(str(today))) as writer:
    df.to_excel(writer, sheet_name='ФСТЭК', index=False)
    print("Ежедневный отчет {}.xlsx создан".format(str(today)))
