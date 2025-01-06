import tldextract
from typing import Set, List, Dict

def normalize_domain(domain: str) -> str:
    """Нормализует домен: нижний регистр и без www."""
    return domain.lower().removeprefix('www.')

def is_subdomain(domain1: str, domain2: str) -> bool:
    """Проверяет, является ли domain1 поддоменом domain2."""
    domain1, domain2 = normalize_domain(domain1), normalize_domain(domain2)
    return domain1 == domain2 or domain1.endswith('.' + domain2)

def analyze_domains(lines: List[str]) -> Set[str]:
    """Анализирует домены и возвращает список доменов для удаления."""
    # Сначала собираем все нормализованные домены (без категорий и пустых строк)
    domains = {}  # domain -> original_line
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            normalized = normalize_domain(stripped)
            domains[normalized] = stripped

    # Находим все домены, которые нужно удалить (поддомены и дубликаты)
    domains_to_remove = set()
    normalized_domains = list(domains.keys())
    
    for domain1 in normalized_domains:
        for domain2 in normalized_domains:
            if domain1 != domain2 and is_subdomain(domain1, domain2):
                domains_to_remove.add(domain1)
                
    return domains_to_remove

def clean_single_file(file_path: str, output_path: str) -> None:
    """Очищает и сортирует домены в одном файле."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Анализируем все домены
        domains_to_remove = analyze_domains(lines)
        
        # Обработка файла
        result = []
        current_category = None
        category_domains = []
        seen_domains = set()  # Для отслеживания уже обработанных доменов

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            
            if stripped.startswith('#'):
                if current_category and category_domains:
                    result.extend([current_category + '\n'] + 
                                sorted(category_domains) + ['\n'])
                current_category = stripped
                category_domains = []
                continue

            normalized_domain = normalize_domain(stripped)
            if normalized_domain not in domains_to_remove and normalized_domain not in seen_domains:
                category_domains.append(normalized_domain + '\n')
                seen_domains.add(normalized_domain)

        # Записываем последнюю категорию
        if current_category and category_domains:
            result.extend([current_category + '\n'] + sorted(category_domains))

        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(result)
        
        print(f"Обработка завершена. Результат записан в {output_path}")

    except FileNotFoundError:
        print(f"Ошибка: Файл не найден: {file_path}")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

def process_two_files(file1_path: str, file2_path: str, output_path: str) -> None:
    """Обрабатывает два файла доменов и записывает результат."""
    try:
        # Читаем оба файла
        with open(file1_path, 'r', encoding='utf-8') as f:
            lines1 = f.readlines()
        with open(file2_path, 'r', encoding='utf-8') as f:
            lines2 = f.readlines()

        # Получаем нормализованные домены из второго файла
        blocked_domains = {normalize_domain(line.strip()) 
                         for line in lines2 
                         if line.strip() and not line.startswith('#')}

        # Анализируем домены из первого файла
        domains_to_remove = analyze_domains(lines1)
        
        # Добавляем домены, которые нужно удалить из-за второго файла
        for line in lines1:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                normalized_domain = normalize_domain(stripped)
                for blocked in blocked_domains:
                    if is_subdomain(normalized_domain, blocked):
                        domains_to_remove.add(normalized_domain)

        # Обработка первого файла
        result = []
        current_category = None
        category_domains = []
        seen_domains = set()

        for line in lines1:
            stripped = line.strip()
            if not stripped:
                continue
            
            if stripped.startswith('#'):
                if current_category and category_domains:
                    result.extend([current_category + '\n'] + 
                                sorted(category_domains) + ['\n'])
                current_category = stripped
                category_domains = []
                continue

            normalized_domain = normalize_domain(stripped)
            if normalized_domain not in domains_to_remove and normalized_domain not in seen_domains:
                category_domains.append(normalized_domain + '\n')
                seen_domains.add(normalized_domain)

        if current_category and category_domains:
            result.extend([current_category + '\n'] + sorted(category_domains))

        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(result)
        
        print(f"Обработка завершена. Результат записан в {output_path}")

    except FileNotFoundError as e:
        print(f"Ошибка: Файл не найден: {e.filename}")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    print("Скрипт для обработки файлов с доменами")
    print("Для обработки только первого файла (очистка и сортировка), нажмите Enter при запросе второго файла")
    
    file1 = input("Введите путь к первому файлу: ").strip()
    file2 = input("Введите путь ко второму файлу (или нажмите Enter для пропуска): ").strip()
    
    if not file1:
        print("Ошибка: необходимо указать первый файл")
    else:
        output = file1.rsplit('.', 1)[0] + "_processed.lst"
        
        if file2:
            process_two_files(file1, file2, output)
        else:
            print("Обработка только первого файла (очистка и сортировка)...")
            clean_single_file(file1, output)