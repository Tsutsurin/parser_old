from progress.bar import IncrementalBar
import functions
import pandas as pd
import re


def main():
    num_pages = functions.num_pages()

    driver = functions.open_driver()

    all_url = []
    source = "ФСТЭК"
    counter = 0

    df = pd.DataFrame(
        {"Источник": [""], "Дата публикации": [""], "CVE": [""], "CVSS": [""], "Продукты": [""], "Ссылки": [""]})

    bar = IncrementalBar("Просмотр страниц", max=num_pages)

    for page in range(1, num_pages + 1):
        soup = functions.get_soup(driver, "https://bdu.fstec.ru/vul?sort=identifier&page=", page)
        tds = soup.find_all("td", class_="col-lg-3 col-xs-3")
        for td in tds:
            links = td.find_all("a", class_="confirm-vul")
            for link in links:
                href = link["href"]
                vul_link = f"https://bdu.fstec.ru{href}"
                all_url.append(vul_link)
        bar.next()

    bar.finish()

    bar = IncrementalBar("Парсинг данных", max=len(all_url))

    for vul_link in all_url:
        try:
            soup = functions.get_soup(driver, vul_link, None)
            tds = soup.find_all("td")

            product = tds[3].text.strip() + " " + tds[5].text.strip()

            cvss = tds[23].text.strip()
            pattern = r"\d+(?:,\d+)?"
            number = re.findall(pattern, cvss)
            size = len(number) - 1
            cvss = number[size].replace(',', '.')

            cve = tds[39].text.strip()

            data = tds[19].text.strip()

            functions.pd_placeholder(df, counter, source, data, cve, cvss, product, vul_link)

            counter += 1
            bar.next()

        except IndexError:
            print(f"Ошибка при обработке {vul_link}")

    bar.finish()
    driver.close()

    functions.do_excel(source, df)


main()
