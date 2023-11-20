from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from datetime import date
import pandas as pd
import re


def get_soup(driver, url_input, page):
    if page is None:
        url = url_input
    else:
        url = f"{url_input}{page}"
    driver.get(url)
    html = driver.page_source
    return BeautifulSoup(html, "lxml")


def num_pages():
    while True:
        try:
            input_number = int(input("Сколько страниц нужно просмотреть? "))
            if input_number < 0:
                print("Введено отрицательное число, попробуйте еще раз")
            elif input_number > 200:
                print("Слишком большое число. Максимум 200 ")
            else:
                return input_number
        except ValueError:
            print("Введите цифры")


def cvss_edited(cvss):
    pattern = r"\d+(?:.\d+)?"
    number = re.findall(pattern, cvss)
    if float(number[0]) < 4:
        return f"{number[0]} Low"
    elif float(number[0]) < 7:
        return f"{number[0]} Medium"
    elif float(number[0]) < 9:
        return f"{number[0]} High"
    else:
        return f"{number[0]} Critical"


def cve_edited(cve):
    # cve = cve.replace("\u00a0", " ")
    matches = re.findall(r"CVE-\d{4}-\d{4,}", cve)
    if matches:
        match = matches[0]
        return match
    else:
        return "-----"


def do_excel(name, df):
    today = date.today()
    today = today.strftime('%d-%m-%Y')
    with pd.ExcelWriter(f"{today} {name}.xlsx") as writer:
        df.to_excel(writer, index=False)
        print(f"Ежедневный отчет {today}.xlsx создан")


def open_driver():
    options = Options()
    options.add_argument("disable-blink-features=AutomationControlled")
    options.add_argument("disable-infobars")
    options.add_argument("start-maximized")
    options.add_argument("ignore-certificate-errors")
    options.add_argument("log-level=3")
    return webdriver.Chrome(options=options)


def pd_placeholder(df, counter, source, data, cve, cvss, product, vul_link):
    df.at[counter, "Источник"] = source
    df.at[counter, "Дата публикации"] = data
    df.at[counter, "CVE"] = cve_edited(cve)
    df.at[counter, "CVSS"] = cvss_edited(cvss)
    df.at[counter, "Продукты"] = product
    df.at[counter, "Ссылки"] = vul_link
    return df
