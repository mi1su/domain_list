#!/usr/bin/python3.13

import requests
import tldextract
import re

def normalize_domain(domain):
    """Приводит домен к нижнему регистру и удаляет префикс 'www.'."""
    return domain.lower().removeprefix("www.")

def download_domains(url):
    """Скачивает список доменов с удаленного URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        domains = [normalize_domain(line.strip()) for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
        print(f"Downloaded {len(domains)} domains from {url}.")
        return domains
    except requests.exceptions.RequestException as e:
        print(f"Error downloading domain list from {url}: {e}")
        raise

def read_local_domains(file_path):
    """Читает список доменов из локального файла."""
    try:
        with open(file_path, 'r', encoding='utf-8') as infile:
            domains = [normalize_domain(line.strip()) for line in infile if line.strip() and not line.startswith("#")]
        print(f"Read {len(domains)} domains from local file {file_path}.")
        return domains
    except FileNotFoundError:
        print(f"Local file {file_path} not found.")
        raise
    except Exception as e:
        print(f"Error reading local file {file_path}: {e}")
        raise

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

def merge_lists(remote_domains, local_domains):
    """Объединяет удаленный и локальный списки доменов и фильтрует дубликаты."""
    normalized_domains = {normalize_domain(dmn) for dmn in remote_domains + local_domains}
    print(f"Merged {len(remote_domains)} remote and {len(local_domains)} local domains.")
    return filter_subdomains(normalized_domains)

def save_merged_list(merged_domains, output_file):
    """Сохраняет объединенный список доменов в файл."""
    try:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(domain + '\n' for domain in sorted(merged_domains))
        print(f"Merged domain list saved to {output_file}")
    except Exception as e:
        print(f"Error saving merged list to {output_file}: {e}")
        raise

def save_nftset_list(merged_domains, nfset_file):
    """Сохраняет список доменов в формате nftset."""
    try:
        with open(nfset_file, 'w', encoding='utf-8') as outfile:
            for domain in sorted(merged_domains):
                outfile.write(f"nftset=/{domain}/4#inet#fw4#vpn_domains\n")
            # outfile.write(f"nftset=/{domain}/6#inet#fw4#vpn_domains\n")
        print(f"NFTables domain list saved to {nfset_file}")
    except Exception as e:
        print(f"Error saving NFTables list to {nfset_file}: {e}")
        raise

def main():
    remote_url = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst"
    blocked_file = "src/blocked_domains.lst"
    restrict_file = "src/restrict_domains.lst"
    output_file = "all_domains.lst"
    nfset_file = "dnsmasq-nfset.lst"

    try:
        print("Downloading remote domain list...")
        remote_domains = download_domains(remote_url)

        print("Reading local blocked domains...")
        blocked_domains = read_local_domains(blocked_file)
        
        print("Reading local restricted domains...")
        restrict_domains = read_local_domains(restrict_file)
        
        # Объединяем домены из двух локальных файлов
        local_domains = blocked_domains + restrict_domains

        print("Merging domain lists...")
        merged_domains = merge_lists(remote_domains, local_domains)

        print("Saving merged lists...")
        save_merged_list(merged_domains, output_file)
        save_nftset_list(merged_domains, nfset_file)

        print(f"Processed {len(remote_domains)} remote domains, {len(blocked_domains)} blocked and {len(restrict_domains)} restricted local domains.")
        print(f"After merging: {len(merged_domains)} domains.")

    except Exception as e:
        print(f"An unexpected error occurred in main: {e}")
        raise

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"A top-level error occurred: {e}")
