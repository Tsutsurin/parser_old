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

for page in range(1, 11):
  url = "https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1=" + str(page)
  link = requests.get(url)
  soup = BeautifulSoup(link.text, "lxml")
  time.sleep(5)

  problem_links = [elem.get("href") for elem in soup.find_all("a", title="Подробнее")]
  problem_url = []
  for i in range(len(problem_links)):
    problem_url.append("https://safe-surf.ru" + problem_links[i])

  source_link = []
  for i in range(len(problem_url)):
    url_junior = problem_url[i]
    link_junior = requests.get(url_junior)
    soup_junior = BeautifulSoup(link_junior.text, "lxml")
    source_element = soup_junior.find("noindex")
    source_link.append(getattr(source_element, "text", None))

  problem_data = [elem.get_text().strip().replace("Дата бюллетеня", "") for elem in soup.find_all(class_ = "cell-bulletin-nkcki cell-1")]
  problem_data = list(filter(bool, problem_data))
  problem_data = [elem.lstrip() for elem in problem_data]

  problem_cve = [elem.get_text().strip().replace("Идентификатор уязвимости", "") for elem in soup.find_all(class_ = "cell-bulletin-nkcki cell-2")]
  problem_cve = list(filter(bool, problem_cve))
  problem_cve = [elem.lstrip() for elem in problem_cve]
  problem_cve = [elem.strip().replace("MITRE:", "") for elem in problem_cve]

  problem_product = [elem.get_text().strip().replace("Уязвимый продукт", "") for elem in soup.find_all(class_ = "cell-bulletin-nkcki cell-3")]
  problem_product = list(filter(bool, problem_product))
  problem_product = [elem.lstrip() for elem in problem_product]
  problem_product = [elem.replace("\n", "") for elem in problem_product]
  problem_product = [re.sub("\s+", " ", elem) for elem in problem_product]

  problem_cvss = [elem.get_text().strip().replace("Уровень опасности", "") for elem in soup.find_all(class_ = "cell-bulletin-nkcki cell-4")]
  problem_cvss = list(filter(bool, problem_cvss))
  problem_cvss = [elem.lstrip() for elem in problem_cvss]
  problem_cvss = [elem.replace("\n", "") for elem in problem_cvss]
  problem_cvss = [re.sub("\s+", " ", elem) for elem in problem_cvss]

  for _ in range(len(problem_data)):
    all_problem_data.append(problem_data[_])
    all_problem_cve.append(problem_cve[_])
    all_problem_cvss.append(problem_cvss[_])
    all_problem_product.append(problem_product[_])
    all_problem_url.append(problem_url[_])
    all_source_link.append(source_link[_])

df = pd.DataFrame({"Дата публикации": all_problem_data,
                    "CVE": all_problem_cve,
                    "CVSS": all_problem_cvss,
                    "Продукт": all_problem_product,
                    "Ссылка": all_problem_url,
                    "Источник": all_source_link})

writer = pd.ExcelWriter('problem_table.xlsx')
df.to_excel(writer, sheet_name='Проблемы', index=False)
writer.close()