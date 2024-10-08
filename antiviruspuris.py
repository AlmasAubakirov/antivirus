import os
import shutil
import psycopg2
import hashlib
from datetime import datetime

# Подключение к базе данных
def connect_db():
    try:
        conn = psycopg2.connect(
            dbname=os.getenv('antivirus_db'),  # Имя базы данных
            user=os.getenv('postgres'),    # Имя пользователя
            password=os.getenv('123456P@$$'), # Пароль
            host=os.getenv('localhost'),     # Хост
            port='5432'                    # Порт по умолчанию
        )
        return conn
    except Exception as e:
        print(f"[ERROR] Не удалось подключиться к базе данных: {e}")
        return None

# Функция для получения сигнатур из базы данных
def get_signatures():
    conn = connect_db()
    if conn is None:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT signature FROM signatures;")
            signatures = cur.fetchall()  # Получаем все сигнатуры
            return [sig[0] for sig in signatures]  # Возвращаем список хешей
    except Exception as e:
        print(f"[ERROR] Не удалось получить сигнатуры из базы данных: {e}")
        return []

# Вычисление хеша файла
def calculate_file_hash(file_path):
    hasher = hashlib.sha256()  # Используем SHA-256 для хеширования
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# Функция для проверки, заражен ли файл
def is_infected(file_path):
    file_hash = calculate_file_hash(file_path)  # Вычисляем хеш файла
    signatures = get_signatures()  # Получаем сигнатуры из базы данных
    return file_hash in signatures  # Проверяем наличие хеша в сигнатурах

# Функция для перемещения файла в карантин
def quarantine_file(file_path):
    quarantine_dir = "КАРАНТИН"  # Путь к папке карантина
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)  # Создает папку, если она не существует
    
    try:
        shutil.copy(file_path, quarantine_dir)  # Копируем файл в карантин
        print(f"[INFO] Файл '{file_path}' перемещен в карантин.")
        insert_quarantine_log(file_path)  # Записываем в базу данных
    except Exception as e:
        print(f"[ERROR] Не удалось переместить файл '{file_path}' в карантин: {e}")

def insert_quarantine_log(file_path):
    conn = connect_db()
    if conn is None:
        return
    try:
        date_quarantined = datetime.now()
        status = 'Карантин'
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO quarantine (file_path, date_quarantined, status)
                VALUES (%s, %s, %s);
            """, (file_path, date_quarantined, status))
        conn.commit()
        print("Данные успешно добавлены в quarantine")
    except Exception as e:
        print(f"[ERROR] Не удалось записать данные в quarantine: {e}")
    finally:
        conn.close()

# Функция для записи истории сканирования в базу данных
def insert_scan_history(start_time, end_time, total_files_scanned, threats_found, action_taken):
    conn = connect_db()
    if conn is None:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO scan_history (start_time, end_time, total_files_scanned, threats_found, action_taken)
                VALUES (%s, %s, %s, %s, %s);
            """, (start_time, end_time, total_files_scanned, threats_found, action_taken))
        conn.commit()
        print("Данные успешно добавлены в scan_history")
    except Exception as e:
        print(f"[ERROR] Не удалось записать данные в scan_history: {e}")
    finally:
        conn.close()
        
def insert_event_logs(event_time, event_type, description):
    conn = connect_db()
    if conn is None:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO event_logs (event_time, event_type, description)
                VALUES (%s, %s, %s);
            """, (event_time, event_type, description))
        conn.commit()
        print("Данные успешно добавлены в event_logs")
    except Exception as e:
        print(f"[ERROR] Не удалось записать данные в event_logs: {e}")
    finally:
        conn.close()

# Основная функция сканирования файлов
def scan_files(directory):
    total_files_scanned = 0
    threats_found = 0
    start_time = datetime.now()

    for root, _, files in os.walk(directory):
        for file in files:
            total_files_scanned += 1
            file_path = os.path.join(root, file)
            if is_infected(file_path):  # Проверка на заражение
                print(f"[WARNING] Найден зараженный файл: {file_path}")
                quarantine_file(file_path)  # Перемещаем файл в карантин
                threats_found += 1

    end_time = datetime.now()
    action_taken = "Файлы перемещены в карантин"
    
    # Записываем результат сканирования в базу данных
    insert_scan_history(start_time, end_time, total_files_scanned, threats_found, action_taken)

# Пример запуска сканирования
if __name__ == "__main__":
    directory_to_scan = "/path/to/scan"  # Укажите путь к директории для сканирования
    scan_files(directory_to_scan)
