import os
import pandas as pd
from bs4 import BeautifulSoup
import re

# Обновленные пути
html_path       = 'C:/Users/........./Threat_Prediction_SBUNIVER-INFRA/Threat Prediction report SBUNIVER-INFRA.html'
csv_dir         = 'C:/Users/........./Threat_Prediction_SBUNIVER-INFRA/Files'
output_file     = 'C:/Users/........./combined_report.xlsx'

"""
в csv_dir нужно сложить файлы из архива с .csv, в которых содержатся списки хостов.
конечный файл будет большим, на анализ отчёта из 150 файлов и 30к строк уходит примерно 40-60 секунд
"""

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
with open(html_path, 'r', encoding='utf-8') as f:
    soup = BeautifulSoup(f.read(), 'html.parser')

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
    
    # Сохраняем результат
    result_df.to_excel(output_file, index=False, engine='openpyxl')
    print(f"Отчёт сохранён: {output_file}")
    print(f"Найдено уязвимостей: {len(vulnerabilities)}")
    print(f"Обработано CSV файлов: {len(final_data)}")
    print(f"Итоговых записей: {len(result_df)}")
    
    # Статистика по отсутствующим файлам
    missing_files = len(vulnerabilities) - len(final_data)
    if missing_files > 0:
        print(f"Предупреждение: {missing_files} CSV файлов не найдено")
else:
    print("Нет данных для сохранения")
