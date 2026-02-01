#!/usr/bin/python3.13

import requests
import tldextract
import pandas as pd
import datetime
import os
from idna import encode as idna_encode
from io import BytesIO

def normalize_domain(domain):
    """Приводит к нижнему регистру, чистит пробелы, убирает www и конвертирует в Punycode."""
    if pd.isna(domain) or domain is None:
        return None
    domain = str(domain).lower().strip().removeprefix("www.")
    # Обработка Punycode (IDNA)
    try:
        if any(ord(c) > 127 for c in domain):
            return idna_encode(domain).decode('utf-8')
    except Exception:
        pass
    return domain

def get_ooni_confirmed(ooni_output):
    """
    Получение ТОЛЬКО подтвержденных блокировок из OONI за месяц.
    Если данных по домену нет или он 'ожил' — он удаляется.
    """
    today = datetime.datetime.now()
    since = (today - datetime.timedelta(days=30)).strftime('%Y-%m-%d')
    until = today.strftime('%Y-%m-%d')
    
    params = {
        "axis_y": "domain",
        "probe_cc": "RU",
        "since": since,
        "until": until,
        "test_name": "web_connectivity",
        "format": "CSV"
    }
    url = f"https://api.ooni.io/api/v1/aggregation?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    
    try:
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        df = pd.read_csv(BytesIO(response.content))
        df = df[pd.notna(df['domain'])]

        blocked_df = df[
            (df.get('confirmed_count', 0) > 0) | 
            ((df['anomaly_count'] > df['ok_count']) & (df['anomaly_count'] > 2))
        ]
        
        ooni_domains = blocked_df['domain'].apply(normalize_domain).dropna().unique().tolist()
        ooni_domains = [d for d in ooni_domains if d and '.' in d]
        
        print(f"OONI API: Found {len(ooni_domains)} active blocked domains this month.")
        return ooni_domains
        
    except Exception as e:
        print(f"OONI update failed: {e}")
        return []

def download_domains(url):
    """Скачивает список доменов с удаленного URL."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        domains = [normalize_domain(line.strip()) for line in response.text.splitlines() 
                   if line.strip() and not line.startswith("#")]
        print(f"Downloaded {len(domains)} domains from {url}.")
        return [d for d in domains if d]
    except requests.exceptions.RequestException as e:
        print(f"Error downloading domain list from {url}: {e}")
        raise

def read_local_domains(file_path):
    """Читает список доменов из локального файла."""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"REQUIRED file missing: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as infile:
            domains = [normalize_domain(line.strip()) for line in infile 
                       if line.strip() and not line.startswith("#")]
        print(f"Read {len(domains)} domains from {os.path.basename(file_path)}")
        return [d for d in domains if d]
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

    print(f"After filtering subdomains: {len(unique_domains)} domains remain")
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
    """Объединяет все источники и фильтрует дубликаты."""
    normalized_domains = set(remote_domains + local_domains)
    print(f"Merged sources: remote={len(remote_domains)}, local={len(local_domains)}")
    return filter_subdomains(normalized_domains)


def save_merged_list(merged_domains, output_file):
    """Сохраняет объединенный список доменов в файл."""
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for domain in sorted(merged_domains):
                outfile.write(domain + '\n')
        print(f"Saved {len(merged_domains)} domains to {output_file}")
    except Exception as e:
        print(f"Error saving merged list to {output_file}: {e}")
        raise

def save_nftset_list(merged_domains, nfset_file):
    """Сохраняет список доменов в формате nftset."""
    try:
        os.makedirs(os.path.dirname(nfset_file), exist_ok=True)
        with open(nfset_file, 'w', encoding='utf-8') as outfile:
            for domain in sorted(merged_domains):
                outfile.write(f"nftset=/{domain}/4#inet#fw4#vpn_domains\n")
        print(f"NFTables domain list saved to {nfset_file}")
    except Exception as e:
        print(f"Error saving NFTables list to {nfset_file}: {e}")
        raise

def main():
    out_dir = "domains"
    src_dir = "src"

    os.makedirs(out_dir, exist_ok=True)
    
    remote_url = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst"
    blocked_file = "src/blocked_domains.lst"
    restrict_file = "src/restrict_domains.lst"
    
    ooni_output = os.path.join(out_dir, "ooni_domains.lst")
    output_file = os.path.join(out_dir, "all_domains.lst")
    nfset_file = os.path.join(out_dir, "dnsmasq_domains.lst")

    print("Fetching OONI monthly confirmed list...")
    ooni_domains = get_ooni_confirmed(ooni_output)
    save_merged_list(ooni_domains, ooni_output)

    print("Downloading remote domain list...")
    remote_domains = download_domains(remote_url)

    print("Reading local domains...")
    local_domains = read_local_domains(blocked_file) + read_local_domains(restrict_file)
    
    print("Merging domain lists (OONI separate)...")
    all_combined = set(ooni_domains) | set(remote_domains) | set(local_domains)
    merged_domains = filter_subdomains(all_combined)


    print("Saving merged lists...")
    save_merged_list(merged_domains, output_file)
    save_nftset_list(merged_domains, nfset_file)

    print(f"Processed: remote={len(remote_domains)}, OONI={len(ooni_domains)}, local={len(local_domains)}")
    print(f"Final unique domains: {len(merged_domains)}.")
    print(f"Files: {ooni_output}, {output_file}, {nfset_file}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        exit(1)