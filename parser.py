from bs4 import BeautifulSoup
import pandas as pd
import requests
import re
import time

all_problem_data = []
all_problem_cve = []
all_problem_cvss = []
all_problem_product = []
all_problem_url = []
all_source_link = []

num_pages = int(input("Введите количество страниц: "))

for page in range(1, num_pages + 1):
    url = "https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1=" + str(page)
    link = requests.get(url)
    soup = BeautifulSoup(link.text, "lxml")
    time.sleep(5)

    problem_links = [elem.get("href") for elem in soup.find_all("a", title="Подробнее")]
    problem_url = ["https://safe-surf.ru" + link for link in problem_links]

    source_link = []
    for url_junior in problem_url:
        link_junior = requests.get(url_junior)
        soup_junior = BeautifulSoup(link_junior.text, "lxml")
        source_element = soup_junior.find("noindex")
        source_link.append(getattr(source_element, "text", None))

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
    problem_product = [re.sub("\s+", " ", elem) for elem in problem_product]

    problem_cvss = [elem.get_text().strip().replace("Уровень опасности", "") for elem in
                    soup.find_all(class_="cell-bulletin-nkcki cell-4")]
    problem_cvss = list(filter(bool, problem_cvss))
    problem_cvss = [elem.lstrip() for elem in problem_cvss]
    problem_cvss = [elem.replace("\n", "") for elem in problem_cvss]
    problem_cvss = [re.sub("\s+", " ", elem) for elem in problem_cvss]

    all_problem_data.extend(problem_data)
    all_problem_cve.extend(problem_cve)
    all_problem_cvss.extend(problem_cvss)
    all_problem_product.extend(problem_product)
    all_problem_url.extend(problem_url)
    all_source_link.extend(source_link)

df = pd.DataFrame({"Дата публикации": all_problem_data,
                   "CVE": all_problem_cve,
                   "CVSS": all_problem_cvss,
                   "Продукт": all_problem_product,
                   "Ссылка": all_problem_url,
                   "Источник": all_source_link})

# Открываем файл через with
with pd.ExcelWriter('problem_table.xlsx') as writer:
    df.to_excel(writer, sheet_name='Проблемы', index=False)
