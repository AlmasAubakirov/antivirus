import os
import shutil
import psycopg2
import hashlib
from datetime import datetime

# Подключение к базе данных
def connect_db():
    print("[INFO] Попытка подключения к базе данных...")
    try:
        conn = psycopg2.connect(
            dbname='antivirus_db',  # Имя базы данных
            user='postgres',    # Имя пользователя
            password='123456P@$$', # Пароль
            host='localhost',     # Хост
            port='5432'                    # Порт по умолчанию
        )
        print("[INFO] Подключение к базе данных успешно!")
        return conn
    except Exception as e:
        print(f"[ERROR] Не удалось подключиться к базе данных: {e}")
        return None

# Функция для получения сигнатур из базы данных
def get_signatures():
    print("[INFO] Получение сигнатур из базы данных...")
    conn = connect_db()
    if conn is None:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT signature FROM signatures;")
            signatures = cur.fetchall()  # Получаем все сигнатуры
            print(f"[INFO] Получено {len(signatures)} сигнатур.")
            return [sig[0] for sig in signatures]  # Возвращаем список хешей
    except Exception as e:
        print(f"[ERROR] Не удалось получить сигнатуры из базы данных: {e}")
        return []

# Вычисление хеша файла
def calculate_file_hash(file_path):
    print(f"[INFO] Вычисление хеша для файла: {file_path}")
    hasher = hashlib.sha256()  # Используем SHA-256 для хеширования
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    file_hash = hasher.hexdigest()
    print(f"[INFO] Хеш файла '{file_path}': {file_hash}")
    return file_hash

# Функция для проверки, заражен ли файл
def is_infected(file_path):
    print(f"[INFO] Проверка файла на заражение: {file_path}")
    file_hash = calculate_file_hash(file_path)  # Вычисляем хеш файла
    signatures = get_signatures()  # Получаем сигнатуры из базы данных
    if file_hash in signatures:
        print(f"[WARNING] Файл '{file_path}' заражен!")
        return True
    else:
        print(f"[INFO] Файл '{file_path}' не заражен.")
        return False

# Функция для перемещения файла в карантин
def quarantine_file(file_path):
    print(f"[INFO] Перемещение файла '{file_path}' в карантин...")
    quarantine_dir = "КАРАНТИН"  # Путь к папке карантина
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)  # Создает папку, если она не существует
        print(f"[INFO] Папка карантина создана: {quarantine_dir}")
    
    try:
        shutil.copy(file_path, quarantine_dir)  # Копируем файл в карантин
        print(f"[INFO] Файл '{file_path}' перемещен в карантин.")
        insert_quarantine_log(file_path)  # Записываем в базу данных
    except Exception as e:
        print(f"[ERROR] Не удалось переместить файл '{file_path}' в карантин: {e}")

def insert_quarantine_log(file_path):
    print(f"[INFO] Запись информации о карантине для файла: {file_path}")
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
        print(f"[INFO] Данные о файле '{file_path}' успешно добавлены в карантин.")
    except Exception as e:
        print(f"[ERROR] Не удалось записать данные в quarantine: {e}")
    finally:
        conn.close()

# Функция для записи истории сканирования в базу данных
def insert_scan_history(start_time, end_time, total_files_scanned, threats_found, action_taken):
    print("[INFO] Запись истории сканирования в базу данных...")
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
        print(f"[INFO] История сканирования успешно добавлена.")
    except Exception as e:
        print(f"[ERROR] Не удалось записать данные в scan_history: {e}")
    finally:
        conn.close()

# Основная функция сканирования файлов
def scan_files(directory):
    print(f"[INFO] Начало сканирования директории: {directory}")
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
    print(f"[INFO] Сканирование завершено. Всего файлов: {total_files_scanned}, Найдено угроз: {threats_found}")

# Пример запуска сканирования
if __name__ == "__main__":
    directory_to_scan = "/home/kali"  # Укажите путь к директории для сканирования
    scan_files(directory_to_scan)
