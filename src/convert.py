#!/usr/bin/python3.13

import tldextract
import urllib.request
import re
import os


def download_file(url, output_file):
    """Скачиваем файл с GitHub."""
    print(f"Downloading file from {url} to {output_file}")
    urllib.request.urlretrieve(url, output_file)
    print(f"File saved to: {os.path.abspath(output_file)}")  # Печать абсолютного пути


def filter_domains(input_file, output_file):
    """Обрабатывает файл, удаляет домены .ua и зеркала."""
    print(f"Processing file: {input_file} -> {output_file}")

    with open(input_file) as infile:
        domains = {line.strip() for line in infile if line.strip()}
    filtered = set()
    grouped_domains = {}
    for domain in domains:
        # Убираем www.
        if domain.startswith("www."):
            domain = domain[4:]
        # Пропускаем домены с .ua
        if domain.endswith(".ua"):
            continue
        # Извлекаем зарегистрированный домен
        ext = tldextract.extract(domain)
        registered_domain = f"{ext.domain}.{ext.suffix}"

        # Группируем зеркала
        if registered_domain not in grouped_domains:
            grouped_domains[registered_domain] = set()
        grouped_domains[registered_domain].add(domain)

    # Убираем дубли, оставляем только основной домен
    for registered_domain, group in grouped_domains.items():
        if len(group) > 1:
            # Если есть домены без www и цифр в начале, берем их
            main_domains = [
                d
                for d in group
                if not re.match(r"^(www\d{1,2}|z\d{1,2}|www\d{1,2}|www)\.", d)
            ]
            if main_domains:
                filtered.add(sorted(main_domains)[0])
            else:
                # Иначе берем самый короткий
                filtered.add(sorted(group, key=len)[0])
        else:
            filtered.add(group.pop())
    # Записываем результат
    with open(output_file, "w") as outfile:
        for domain in sorted(filtered):
            outfile.write(f"{domain}\n")
    print(f"Filtered file saved to: {os.path.abspath(output_file)}")  # Печать пути сохраненного файла


def combine_files(input_files, output_file):
    """Объединяет файлы в итоговый список."""
    print(f"Combining files: {', '.join(input_files)} -> {output_file}")
    combined = set()

    for file in input_files:
        with open(file) as infile:
            combined.update(line.strip() for line in infile if line.strip())
    # Записываем объединённый список
    with open(output_file, "w") as outfile:
        for domain in sorted(combined):
            outfile.write(f"{domain}\n")
    print(f"Combined file saved to: {os.path.abspath(output_file)}")  # Печать пути сохраненного файла


def generate_dnsmasq(input_file, output_file):
    """Создаёт файл dnsmasq-nfset.lst."""
    print(f"Generating dnsmasq file from {input_file} -> {output_file}")
    with open(input_file) as infile:
        domains = {line.strip() for line in infile if line.strip()}
    # Записываем настройки в файл
    with open(output_file, "w") as outfile:
        for domain in sorted(domains):
            outfile.write(f"nftset=/{domain}/4#inet#fw4#vpn_domains\n")
            # outfile.write(f"nftset=/{domain}/6#inet#fw4#vpn_domains\n")
    print(f"DNSMasq file saved to: {os.path.abspath(output_file)}")  # Печать пути сохраненного файла


def cleanup_temp_files(*files):
    """Удаляет временные файлы."""
    for file in files:
        if os.path.exists(file):
            os.remove(file)
            print(f"Deleted temporary file: {file}")
        else:
            print(f"File not found: {file}")


if __name__ == "__main__":
    try:
        # Скачиваем файл
        download_file(
            "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst",
            "domains_all.lst",
        )

        # Обрабатываем скачанный файл
        filter_domains("domains_all.lst", "processed.lst")

        # Объединяем с локальным файлом
        combine_files(["processed.lst", "src/domains.lst"], "all_domains.lst")

        # Генерируем файл для dnsmasq
        generate_dnsmasq("all_domains.lst", "dnsmasq-nfset.lst")

        # Удаляем временные файлы
        cleanup_temp_files("processed.lst", "domains_all.lst")
    except Exception as e:
        print(f"An error occurred: {e}")
