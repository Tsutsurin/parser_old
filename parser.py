from selenium import webdriver
from selenium.webdriver.edge.service import Service
from collections import Counter
from bs4 import BeautifulSoup
from datetime import datetime
from datetime import date
import pandas as pd
import os.path
import time
import re

source = []
status = []
all_problem_data = []
all_problem_cve = []
all_problem_cvss = []
all_problem_product = []
all_problem_url = []
all_problem_cve_edited = []
all_problem_cvss_edited = []

action = 0
while action == 0:
    print("Press 1 to search for new vulnerabilities ")
    print("Press 2 to create a Vulnerabilly table")
    action = int(input())
    if action == 1 or action == 2:
        num_pages = int(input("how many pages FSTEK? "))
        num_pages_nktski = int(input("how many pages NKTSKI? "))
    else:
        print("Something went wrong, use 1 or 2")
        action = 0

if action == 1:
    df_old = pd.read_excel("Vulnerability table.xlsx")
    old_cve = df_old["CVE"].tolist()
    old_url = df_old["Ссылка"].tolist()
    if not os.path.exists("Vulnerability table.xlsx"):
        action = 2
        num_pages = int(input("how many pages FSTEK? "))
        num_pages_nktski = int(input("how many pages NKTSKI? "))

service = Service(r'utilities/msedgedriver.exe')
options = webdriver.EdgeOptions()

options.add_argument("--disable-blink-features=AutomationControlled")
options.add_argument("--disable-infobars")
options.add_argument("--start-maximized")
options.add_argument("--ignore-certificate-errors")
options.add_argument("--log-level=3")
# options.add_argument("--headless")

driver = webdriver.Edge(options=options, service=service)
print("Please wait, the work has begun")
for page in range(1, num_pages + 1):
    url = "https://bdu.fstec.ru/vul?sort=datv&page=" + str(page)
    driver.get(url)
    html = driver.page_source
    soup = BeautifulSoup(html, "lxml")

    tds = soup.find_all("td", class_="col-lg-3 col-xs-3")
    for td in tds:
        links = td.find_all("a", class_="confirm-vul")
        for link in links:
            href = link["href"]
            vul_link = "https://bdu.fstec.ru" + href
            if action == 1:
                if vul_link in old_url:
                    pass
                else:
                    print("New vulnerability found " + vul_link)
                    all_problem_url.append(vul_link)
            else:
                all_problem_url.append(vul_link)

for vul_link in all_problem_url:
    driver.get(vul_link)
    html = driver.page_source
    soup = BeautifulSoup(html, "lxml")

    tds = soup.find_all("td")
    problem_product = tds[3].text.strip() + " " + tds[5].text.strip()

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
    all_problem_product.append(problem_product)
    all_problem_data.append(tds[19].text.strip())

# NKTSKI
for page in range(1, num_pages_nktski + 1):
    url = "https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1=" + str(page)
    time.sleep(5)
    driver.get(url)
    html = driver.page_source
    soup = BeautifulSoup(html, "lxml")

    problem_links = [elem.get("href") for elem in soup.find_all("a", title="Подробнее")]
    problem_url = ["https://safe-surf.ru" + link for link in problem_links]
    if action == 1:
        size_for_repeat = len(problem_url)
        counter = []
        for i in range(size_for_repeat):
            if problem_url[i] in old_url:
                pass
            else:
                print("New vulnerability found " + problem_url[i])
                counter.append(i)

        if not counter:
            counter = 0
        else:
            counter = counter[-1]
    else:
        counter = len(problem_url)

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

    for i in range(counter):
        all_problem_cve.append(problem_cve[i])
        all_problem_cvss.append(problem_cvss[i])
        all_problem_data.append(problem_data[i])
        all_problem_product.append(problem_product[i])
        all_problem_url.append(problem_url[i])
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

if action == 1:
    for i in range(len(all_problem_cve_edited)):
        status.append("Новый")
        for j in old_cve:
            if all_problem_cve_edited[i] == j:
                status[i] = "Повтор"

else:
    counter = Counter(all_problem_cve_edited)
    dates = [datetime.strptime(date, "%d.%m.%Y") for date in all_problem_data]
    for index, value in enumerate(all_problem_cve_edited):
        if value == "Zero-day":
            status.append("Новый")
        else:
            if counter[value] > 1:
                indices = [i for i, x in enumerate(all_problem_cve_edited) if x == value]
                dates_list = [dates[i] for i in indices]
                min_date = min(dates_list)
                if dates[index] == min_date:
                    status.append("Новый")
                else:
                    if dates[index] > min_date:
                        status.append("Повтор")
            else:
                status.append("Новый")

check = len(all_problem_url)
while len(source) != check:
    source.append("-")
while len(all_problem_data) != check:
    all_problem_data.append("-")
while len(status) != check:
    status.append("-")
while len(all_problem_cve_edited) != check:
    all_problem_cvss_edited.append("-")
while len(all_problem_product) != check:
    all_problem_product.append("-")

df = pd.DataFrame({"Источник": source,
                   "Дата публикации": all_problem_data,
                   "Статус": status,
                   "CVE": all_problem_cve_edited,
                   "CVSS": all_problem_cvss_edited,
                   "Продукт": all_problem_product,
                   "Ссылка": all_problem_url})

if action == 1:
    today = date.today()
    df_new = pd.concat([df_old, df])
    with pd.ExcelWriter("Vulnerability table.xlsx") as writer:
        df_new.to_excel(writer, sheet_name='Проблемы', index=False)
        print("Table overwritten")
    with pd.ExcelWriter(str(today) + ".xlsx") as writer:
        df.to_excel(writer, sheet_name='Проблемы', index=False)
        print("Daily table created")
else:
    with pd.ExcelWriter("Vulnerability table.xlsx") as writer:
        df.to_excel(writer, sheet_name='Проблемы', index=False)
        print("Table created")