# импортируем библиотеки
from selenium import webdriver
from selenium.webdriver.edge.service import Service
from bs4 import BeautifulSoup
import time
import random

# задаем адрес и порт прокси-сервера
#proxy_host = "http://corp%5CTsutsurinNV:M4s8g126@@db24-tmgproxy.corp.lukoil.com"
#proxy_port = "3128"

# создаем объект сервиса для драйвера Edge
service = Service(r'msedgedriver.exe')

# создаем объект опций для браузера Edge
options = webdriver.EdgeOptions()

# добавляем аргументы для скрытия webdriver и игнорирования ошибок сертификата
options.add_argument("--disable-blink-features=AutomationControlled")
options.add_argument("--disable-infobars")
options.add_argument("--start-maximized")
options.add_argument("--ignore-certificate-errors")
#options.add_argument("--headless")
#options.add_argument(f"--proxy-server={proxy_host}:{proxy_port}")

# создаем объект драйвера для браузера Edge с заданными опциями и сервисом
driver = webdriver.Edge(options=options, service=service)

# задаем ссылку для скачивания файла
url = "https://bdu.fstec.ru/vul?sort=datv"

# открываем веб-страницу по ссылке
driver.get(url)

# получаем HTML-код страницы
html = driver.page_source

# ждем, пока загрузится страница
time.sleep(random.uniform(3, 5))

# создаем объект BeautifulSoup из HTML-кода
soup = BeautifulSoup(html, "lxml")

# находим все элементы <td> с классом col-lg-3 col-xs-3
tds = soup.find_all("td", class_="col-lg-3 col-xs-3")

# создаем пустой список для хранения ссылок на уязвимости
vul_links = []

# проходим по всем найденным элементам <td>
for td in tds:
    # находим все элементы <a> с классом confirm-vul внутри текущего элемента <td>
    links = td.find_all("a", class_="confirm-vul")

    # проходим по всем найденным элементам <a>
    for link in links:
        # получаем атрибут href, который содержит относительную ссылку на уязвимость
        href = link["href"]

        # добавляем к относительной ссылке базовый адрес сайта, чтобы получить абсолютную ссылку
        vul_link = "https://bdu.fstec.ru" + href

        # добавляем абсолютную ссылку в список
        vul_links.append(vul_link)

# выводим список ссылок на уязвимости
print(vul_links)

# создаем пустой список для хранения информации об уязвимостях
vul_infos = []

# проходим по всем элементам списка vul_links
for vul_link in vul_links:
    # открываем ссылку в новой вкладке браузера
    driver.execute_script(f"window.open('{vul_link}');")

    # переключаемся на новую вкладку браузера
    driver.switch_to.window(driver.window_handles[-1])

    # получаем HTML-код страницы
    html = driver.page_source

    # ждем, пока загрузится страница
    time.sleep(random.uniform(3, 5))

    # создаем объект BeautifulSoup из HTML-кода
    soup = BeautifulSoup(html, "lxml")
    #table = soup.find(class_="table table-striped attr-view-table")
    #print(table)
    tds = soup.find_all("td")
    for i in range(40):
        print(i)
        print(tds[i])

# выводим список словарей с информацией об уязвимостях
print(vul_infos)

# закрываем драйвер
driver.close()

#3 и 5 - вендо по, 19 - дата, 23 -  cvss, 39 - cve
