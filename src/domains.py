#!/usr/bin/python3.13

import requests
import tldextract
import datetime
import os
from idna import encode as idna_encode

def normalize_domain(domain):
    """Приводит к нижнему регистру, чистит пробелы, убирает www и конвертирует в Punycode."""
    domain = domain.lower().strip().removeprefix("www.")
    # Обработка Punycode (IDNA)
    try:
        if any(ord(c) > 127 for c in domain):
            return idna_encode(domain).decode('utf-8')
    except Exception:
        pass
    return domain

def get_ooni_confirmed():
    """Получение подтвержденных блокировок из OONI API."""
    until_date = datetime.datetime.now().strftime('%Y-%m-%d')
    since_date = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime('%Y-%m-%d')
    ooni_url = f"https://api.ooni.io/api/v1/measurements?probe_cc=RU&since={since_date}&until={until_date}&confirmed=true"
    
    response = requests.get(ooni_url)
    response.raise_for_status()
    data = response.json()
    domains = set()
    for result in data.get('results', []):
        url = result.get('input', '')
        if url:
            domain = url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            domain = normalize_domain(domain)
            if domain and '.' in domain:
                domains.add(domain)
    print(f"OONI: Collected {len(domains)} domains.")
    return list(domains)

def download_domains(url):
    """Скачивает список доменов с удаленного URL."""
    response = requests.get(url)
    response.raise_for_status()
    domains = [normalize_domain(line.strip()) for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
    print(f"Downloaded {len(domains)} domains from {url}.")
    return domains

def read_local_domains(file_path):
    """Читает список доменов из локального файла."""
    with open(file_path, 'r', encoding='utf-8') as infile:
        domains = [normalize_domain(line.strip()) for line in infile if line.strip() and not line.startswith("#")]
    print(f"Read {len(domains)} domains from local file {file_path}.")
    return domains

def filter_subdomains(domains):
    """
    Фильтрует поддомены верхнего уровня (TLD) и фильтрует домены, оставляя
    только один из группы похожих доменов.
    """
    top_level_domains = set()
    unique_domains = set()
    domains_by_base = {}

    for domain in domains:
        extracted = tldextract.extract(domain)
        if not extracted.domain and '.' not in extracted.suffix:
            tld = "." + extracted.suffix
            top_level_domains.add(tld)
            unique_domains.add(tld)
            continue
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        if extracted.suffix:
            if base_domain not in domains_by_base:
                domains_by_base[base_domain] = set()
            domains_by_base[base_domain].add(domain)

    for base_domain, subdomains in domains_by_base.items():
        if any(base_domain.endswith(tld) for tld in top_level_domains):
            continue
        if base_domain in subdomains:
            unique_domains.add(base_domain)
        else:
            unique_domains.update(subdomains)

    print(f"After filtering subdomains, {len(unique_domains)} domains remain.")
    return sorted(unique_domains)

def clear_domain(domains):
    """
    Обрабатывает "зеркала" доменов, оставляя только один из похожих.

    Предполагается, что на вход подаются домены уже прошедшие фильтрацию
    функцией filter_subdomains.
    """
    domains_by_base = {}
    unique_domains = set()

    for domain in domains:
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        if base_domain not in domains_by_base:
            domains_by_base[base_domain] = set()
        domains_by_base[base_domain].add(domain)

    for base_domain, related_domains in domains_by_base.items():
        if len(related_domains) > 1:
            related_domains_list = list(related_domains)
            related_domains_list.sort()
            unique_domains.add(related_domains_list[0])
        else:
            unique_domains.update(related_domains)

    print(f"After removing mirror domains, {len(unique_domains)} unique domains remain.")
    return sorted(unique_domains)

def merge_lists(remote_domains, ooni_domains, local_domains):
    """Объединяет все источники и фильтрует дубликаты."""
    normalized_domains = {normalize_domain(dmn) for dmn in remote_domains + ooni_domains + local_domains}
    print(f"Merged sources: {len(remote_domains)} remote, {len(ooni_domains)} ooni, {len(local_domains)} local.")
    return filter_subdomains(normalized_domains)

def save_merged_list(merged_domains, output_file):
    """Сохраняет объединенный список доменов в файл."""
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.writelines(domain + '\n' for domain in sorted(merged_domains))
    print(f"Merged domain list saved to {output_file}")


def save_nftset_list(merged_domains, nfset_file):
    """Сохраняет список доменов в формате nftset."""
    with open(nfset_file, 'w', encoding='utf-8') as outfile:
        for domain in sorted(merged_domains):
            outfile.write(f"nftset=/{domain}/4#inet#fw4#vpn_domains\n")
            # outfile.write(f"nftset=/{domain}/6#inet#fw4#vpn_domains\n")
    print(f"NFTables domain list saved to {nfset_file}")

def main():
    out_dir = "domains"
    os.makedirs(out_dir, exist_ok=True)
    
    remote_url = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst"
    blocked_file = "src/blocked_domains.lst"
    restrict_file = "src/restrict_domains.lst"
    
    # Пути к файлам
    ooni_output = os.path.join(out_dir, "ooni_domains.lst")
    output_file = os.path.join(out_dir, "all_domains.lst")
    nfset_file = os.path.join(out_dir, "dnsmasq_domains.lst")

    print("Fetching OONI confirmed list...")
    ooni_raw = get_ooni_confirmed()
    ooni_domains = filter_subdomains(ooni_raw)
    save_merged_list(ooni_domains, ooni_output)

    print("Downloading remote domain list...")
    remote_domains = download_domains(remote_url)

    print("Reading local domains...")
    local_domains = read_local_domains(blocked_file) + read_local_domains(restrict_file)
    
    print("Merging domain lists...")
    merged_domains = merge_lists(remote_domains, ooni_domains, local_domains)

    print("Saving merged lists...")
    save_merged_list(merged_domains, output_file)
    save_nftset_list(merged_domains, nfset_file)

    print(f"Processed: {len(remote_domains)} remote, {len(ooni_domains)} ooni, {len(local_domains)} local.")
    print(f"Final unique domains: {len(merged_domains)}.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"A top-level error occurred: {e}")
        exit(1)