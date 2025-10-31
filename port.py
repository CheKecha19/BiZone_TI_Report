import os
import pandas as pd
from bs4 import BeautifulSoup
import re
import glob
from datetime import datetime
from pathlib import Path
import ipaddress

# Обновленные пути
base_dir = Path(__file__).parent
report_dir = base_dir / "Threat_Prediction_SBUNIVER-INFRA"
csv_dir = base_dir / "Threat_Prediction_SBUNIVER-INFRA/Files"

# Находим самый свежий HTML файл в папке
html_files = list(report_dir.glob("*.html"))
if not html_files:
    print("Не найден ни один HTML файл в папке Threat_Prediction_SBUNIVER-INFRA")
    exit(1)

# Выбираем самый новый файл по дате изменения
html_path = max(html_files, key=os.path.getmtime)
print(f"Используется файл: {html_path.name}")

# Добавляем дату к имени файла
current_date = datetime.now()
month_year = f"_{current_date.month:02d}_{current_date.year}"
output_file = os.path.join(base_dir, f'combined_report{month_year}.xlsx')

def get_host_info(ip_str, hostname=None):
    if not ip_str or pd.isna(ip_str):
        return "", "", ""
    
    # Преобразуем в строку и убираем пробелы
    ip_str = str(ip_str).strip()
    
    # Функция для проверки принадлежности IP к сети
    def is_in_network(ip, network):
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
        except:
            return False
    
    # Проверяем каждый IP из введенной строки
    for ip_item in ip_str.split(','):
        ip = ip_item.strip()
        if not ip:  # Пропускаем пустые строки
            continue
            
        try:
            # Сначала проверяем специфичные подсети 25.55.x.x, которые должны иметь приоритет над общей сетью кампуса
            # VDC08 
            if (is_in_network(ip, '25.55.112.0/24') or 
                is_in_network(ip, '25.55.124.0/24')):
                return "Морозов", "облако", "VDC08"
            
            # VDC10
            elif (is_in_network(ip, '25.55.127.0/24')):
                return "Морозов", "облако", "VDC10"
            
            # Кампус пользовательские пк (теперь эта проверка идет ПОСЛЕ специфичных VDC08/10)
            elif (is_in_network(ip, '25.55.0.0/16') or
                  is_in_network(ip, '192.168.0.0/16')):
                return "ОИТ", "кампус", "кампус"

            # VDC01
            elif (is_in_network(ip, '10.12.0.0/24') or 
                  is_in_network(ip, '10.14.0.0/24') or
                  is_in_network(ip, '10.15.0.0/24') or
                  is_in_network(ip, '10.16.0.0/24') or
                  is_in_network(ip, '10.17.0.0/24')):
                return "Смолин", "облако", "VDC01"
            
            # VDC02
            elif (is_in_network(ip, '10.11.11.0/24') or 
                  is_in_network(ip, '188.72.106.0/24')):
                return "Комиссаров", "облако", "VDC02"
            
            # VDC03
            elif (is_in_network(ip, '10.10.0.0/24') or 
                  is_in_network(ip, '10.10.1.0/24') or
                  is_in_network(ip, '10.10.10.0/24') or
                  is_in_network(ip, '10.7.0.0/24') or
                  is_in_network(ip, '10.129.0.0/24')):
                return "Смолин", "облако", "VDC03"
            
            # VDC04
            elif (is_in_network(ip, '192.168.199.0/24')):
                return "Ходик", "облако", "VDC04"
            
            # VDC05
            elif (is_in_network(ip, '10.11.12.0/24')):
                return "Крамарева", "облако", "VDC05"
            
            # VDC06
            elif (is_in_network(ip, '10.130.0.0/24') or 
                  is_in_network(ip, '10.30.0.0/24') or 
                  is_in_network(ip, '10.30.10.0/24') or 
                  is_in_network(ip, '10.8.0.0/24')):
                return "Смолин", "облако", "VDC06"
            
            # VDC07
            elif (is_in_network(ip, '10.100.0.0/24') or 
                  is_in_network(ip, '10.99.0.0/16') or 
                  is_in_network(ip, '172.27.0.0/24') or 
                  is_in_network(ip, '37.18.111.0/24')):
                return "Красильников", "облако", "VDC07"
            
            # VDC09
            elif (is_in_network(ip, '10.13.0.0/24') or 
                  is_in_network(ip, '10.18.0.0/24')):
                return "Смолин", "облако", "VDC09"
            
            # VDC11
            elif (is_in_network(ip, '192.168.3.0/24')):
                return "Ходик", "облако", "VDC11"
            
            # VDC13
            elif (is_in_network(ip, '10.13.1.0/24')):
                return "Комиссаров", "облако", "VDC13"
            
            # VDC15
            elif (is_in_network(ip, '10.64.0.0/24') or 
                  is_in_network(ip, '10.24.0.0/16') or 
                  is_in_network(ip, '10.14.1.0/24')):
                return "Меркулова", "облако", "VDC15"
            
            # VDC16
            elif (is_in_network(ip, '10.74.0.0/16') or 
                  is_in_network(ip, '10.44.1.0/24')):
                return "Меркулова", "облако", "VDC16"
            
            # VDC17
            elif (is_in_network(ip, '10.84.0.0/16')):
                return "Меркулова", "облако", "VDC17"
            
            # VDC18
            elif (is_in_network(ip, '10.19.0.0/24')):
                return "Смолин", "облако", "VDC18"

        except ValueError:
            continue
    
    # Если IP не подходит ни под одно правило, проверяем по имени хоста
    if hostname and not pd.isna(hostname):
        hostname_str = str(hostname).strip()
        
        # Регистронезависимая проверка префиксов имен хостов
        hostname_lower = hostname_str.lower()
        if (hostname_lower.startswith('cu-nbk-') or 
            hostname_lower.startswith('15-pf') or 
            hostname_lower.startswith('16-pf') or
            hostname_lower.startswith('cuhp5')):
            return "ОИТ", "кампус", "кампус"
    
    # Если ничего не найдено
    return "", "", ""

# Функция для извлечения текста до следующего заголовка
def extract_content(header):
    content = []
    next_sib = header.find_next_sibling()
    
    while next_sib and next_sib.name not in ['h2', 'h3', 'h4']:
        if next_sib.name in ['p', 'div', 'ol', 'ul', 'pre']:
            # Для списков обрабатываем отдельно
            if next_sib.name in ['ol', 'ul']:
                list_items = next_sib.find_all('li')
                for idx, item in enumerate(list_items):
                    prefix = f"{idx+1}. " if next_sib.name == 'ol' else "- "
                    content.append(prefix + item.get_text(strip=True))
            else:
                text = next_sib.get_text(strip=True)
                if text:
                    content.append(text)
        next_sib = next_sib.next_sibling
    
    return '\n'.join(content)

# Парсинг HTML
try:
    with open(html_path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')
except Exception as e:
    print(f"Ошибка чтения файла {html_path}: {e}")
    exit(1)

# Собираем данные
vulnerabilities = []
current_severity = ""

# Ищем все заголовки
for header in soup.find_all(['h2', 'h3', 'h4']):
    if header.name == 'h2' and 'data-title' in header.attrs:
        current_severity = header['data-title'].strip()
    
    elif header.name == 'h3' and 'data-title' in header.attrs:
        vuln = {
            'severity': current_severity,
            'name': header['data-title'].strip(),
            'description': '',
            'recommendation': '',
            'rule': ''
        }
        vulnerabilities.append(vuln)
    
    elif header.name == 'h4' and vulnerabilities:
        text = header.get_text(strip=True)
        
        if text == 'Описание':
            vulnerabilities[-1]['description'] = extract_content(header)
        
        elif text == 'Рекомендации':
            vulnerabilities[-1]['recommendation'] = extract_content(header)
        
        elif text == 'Сработавшее правило':
            badge = header.find_next(class_='badge')
            if badge:
                vulnerabilities[-1]['rule'] = badge.get_text(strip=True)

# Обработка CSV и создание финального DataFrame
final_data = []

for vuln in vulnerabilities:
    if not vuln['rule']:
        continue
        
    # Формируем имя файла
    filename = f"SBUNIVER-INFRA_{vuln['rule']}.csv"
    filepath = os.path.join(csv_dir, filename)
    
    if not os.path.exists(filepath):
        print(f"Файл не найден: {filename}")
        continue
        
    # Читаем CSV
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        print(f"Ошибка чтения {filename}: {str(e)}")
        continue
        
    # Добавляем метаданные уязвимости
    for col in ['severity', 'name', 'description', 'recommendation']:
        df[col] = vuln[col]
    
    # Переупорядочиваем столбцы
    base_cols = ['severity', 'name', 'description', 'recommendation']
    other_cols = [col for col in df.columns if col not in base_cols]
    df = df[base_cols + other_cols]
    
    final_data.append(df)

# Объединяем все данные
if final_data:
    result_df = pd.concat(final_data, ignore_index=True)
    
    # Добавляем три новых столбца в начало
    result_df.insert(0, '#VDC', '')
    result_df.insert(0, 'Расположение', '')
    result_df.insert(0, 'Ответственный', '')
    
    # Заполняем автоматически, если есть столбец с IP
    if 'dev_ipv4' in result_df.columns:
        # Используем конкретное имя столбца dev_fqdn для хостов
        hostname_column = 'dev_fqdn' if 'dev_fqdn' in result_df.columns else None
        
        for idx, row in result_df.iterrows():
            ip = row['dev_ipv4']
            hostname = row[hostname_column] if hostname_column else None
            
            # Получаем информацию по IP и имени хоста
            responsible, location, vdc = get_host_info(ip, hostname)
            
            # Заполняем только если значения еще не установлены
            current_responsible = result_df.at[idx, 'Ответственный']
            current_location = result_df.at[idx, 'Расположение']
            current_vdc = result_df.at[idx, '#VDC']
            
            if not current_responsible and not current_location and not current_vdc:
                result_df.at[idx, 'Ответственный'] = responsible
                result_df.at[idx, 'Расположение'] = location
                result_df.at[idx, '#VDC'] = vdc
    
    # Создаем ExcelWriter для записи нескольких листов
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        # Сохраняем основной отчет
        result_df.to_excel(writer, sheet_name='Отчет', index=False)
        
        # Статистика по отсутствующим файлам
        missing_files = len(vulnerabilities) - len(final_data)
        
        # Поиск предыдущего отчета для сравнения
        previous_reports = glob.glob(os.path.join(base_dir, 'combined_report_*.xlsx'))
        previous_reports.sort(key=os.path.getmtime, reverse=True)
        
        # Ищем последний отчет, кроме текущего
        previous_report = None
        for report in previous_reports:
            if report != output_file:
                previous_report = report
                break
        
        comparison_data = []
        
        if previous_report:
            # Извлекаем даты из имен файлов
            current_date_str = os.path.basename(output_file).split('_')[-2] + '_' + os.path.basename(output_file).split('_')[-1].split('.')[0]
            prev_date_str = os.path.basename(previous_report).split('_')[-2] + '_' + os.path.basename(previous_report).split('_')[-1].split('.')[0]
            
            # Загружаем текущий и предыдущий отчеты
            df_current = result_df
            df_previous = pd.read_excel(previous_report)
            
            # Сравниваем количество записей по каждой уязвимости
            comparison_results = []
            
            # Уникальные имена уязвимостей
            all_names = set(df_current['name'].unique()).union(set(df_previous['name'].unique()))
            
            print("\nСравнение количества записей по уязвимостям:")
            for name in sorted(all_names):
                count_current = len(df_current[df_current['name'] == name]) if name in df_current['name'].values else 0
                count_previous = len(df_previous[df_previous['name'] == name]) if name in df_previous['name'].values else 0
                
                # Определяем тип изменения
                if count_previous == 0 and count_current > 0:
                    status = "новое"
                    diff_str = f"+{count_current}"
                elif count_previous > 0 and count_current == 0:
                    status = "устранено"
                    diff_str = f"-{count_previous}"
                else:
                    # Рассчитываем разницу
                    diff = count_current - count_previous
                    
                    # Форматируем разницу
                    if diff > 0:
                        diff_str = f"+{diff}"
                        status = "рост"
                    elif diff < 0:
                        diff_str = f"{diff}"  # отрицательное число уже содержит знак минус
                        status = "снижение"
                    else:
                        diff_str = "0"
                        status = "без изменений"
                
                # Формируем строку для вывода
                result_line = f'name: "{name}"; {diff_str}; {status}'
                comparison_results.append(result_line)
                
                # Добавляем данные для DataFrame
                comparison_data.append({
                    'Уязвимость': name,
                    'Разница': diff_str,
                    'Статус': status,
                    'Текущее количество': count_current,
                    'Предыдущее количество': count_previous
                })
                
                print(result_line)
            
            # Создаем DataFrame для сравнения
            comparison_df = pd.DataFrame(comparison_data)
            
            # Сохраняем сравнение на отдельный лист
            comparison_df.to_excel(writer, sheet_name='Сравнение', index=False)
            
            # Сохраняем результаты сравнения в файл
            change_file = os.path.join(base_dir, f'change_{prev_date_str}_{current_date_str}.txt')
            with open(change_file, 'w', encoding='utf-8') as f:
                f.write(f'Сравнение отчетов: {prev_date_str} (до) и {current_date_str} (после)\n\n')
                f.write("\n".join(comparison_results))
            
            print(f"\nРезультаты сравнения сохранены в: {change_file}")
        else:
            print("\nПредыдущий отчет не найден для сравнения")
            # Создаем пустой DataFrame для сравнения
            pd.DataFrame(columns=['Уязвимость', 'Разница', 'Статус', 'Текущее количество', 'Предыдущее количество']).to_excel(writer, sheet_name='Сравнение', index=False)
    
    print(f"Отчёт сохранён: {output_file}")
    print(f"Найдено уязвимостей: {len(vulnerabilities)}")
    print(f"Обработано CSV файлов: {len(final_data)}")
    print(f"Итоговых записей: {len(result_df)}")
    
    if missing_files > 0:
        print(f"Предупреждение: {missing_files} CSV файлов не найдено")
else:
    print("Нет данных для сохранения")