import os
import shutil
import psycopg2
import hashlib
import requests
import schedule
import time
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from tkinter import ttk

# Подключение к базе данных
def connect_db():
    try:
        conn = psycopg2.connect(
            dbname='antivirus_db',  # Имя базы данных
            user='postgres',    # Имя пользователя
            password='123456P@$$', # Пароль
            host='localhost',     # Хост
            port='5432'                    # Порт по умолчанию
        )
        return conn
    except Exception as e:
        messagebox.showerror("Database Error", f"Не удалось подключиться к базе данных: {e}")
        return None

# Получение сигнатур из базы данных
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
        messagebox.showerror("Error", f"Не удалось получить сигнатуры: {e}")
        return []

# Вычисление хеша файла
def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# Проверка на заражение
def is_infected(file_path):
    file_hash = calculate_file_hash(file_path)
    signatures = get_signatures()
    return file_hash in signatures

# Перемещение файла в карантин
def quarantine_file(file_path):
    quarantine_dir = "КАРАНТИН"
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    
    try:
        shutil.copy(file_path, quarantine_dir)
        insert_quarantine_log(file_path)
        messagebox.showinfo("Quarantine", f"Файл '{file_path}' перемещен в карантин.")
    except Exception as e:
        messagebox.showerror("Error", f"Не удалось переместить файл в карантин: {e}")

# Запись в карантин лог
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
    except Exception as e:
        messagebox.showerror("Error", f"Не удалось записать данные: {e}")
    finally:
        conn.close()

# Сканирование файлов
def scan_files(directory):
    total_files_scanned = 0
    threats_found = 0
    start_time = datetime.now()

    # Создаем и настраиваем полосу выполнения
    progress_bar = ttk.Progressbar(main_content, orient="horizontal", mode="determinate")
    progress_bar.pack(pady=20, fill='x')
    
    # Получаем общее количество файлов для настройки полосы выполнения
    total_files = sum([len(files) for _, _, files in os.walk(directory)])
    progress_bar["maximum"] = total_files  # Устанавливаем максимальное значение

    for root, _, files in os.walk(directory):
        for file in files:
            total_files_scanned += 1
            file_path = os.path.join(root, file)
            if is_infected(file_path):
                quarantine_file(file_path)
                threats_found += 1
            
            progress_bar["value"] = total_files_scanned  # Обновляем значение полосы выполнения
            root.update_idletasks()  # Обновляем интерфейс

    end_time = datetime.now()
    action_taken = "Файлы перемещены в карантин"
    insert_scan_history(start_time, end_time, total_files_scanned, threats_found, action_taken)

    progress_bar.destroy()  # Удаляем полосу выполнения после завершения сканирования
    messagebox.showinfo("Scan Complete", f"Всего файлов: {total_files_scanned}, Найдено угроз: {threats_found}")


# Запись истории сканирования
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
    except Exception as e:
        messagebox.showerror("Error", f"Не удалось записать историю сканирования: {e}")
    finally:
        conn.close()

# Получение сигнатур вирусов через API VirusTotal
def fetch_signatures_from_api():
    api_key = os.getenv('VT_API_KEY')  # Используйте свой API ключ VirusTotal
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
        'apikey': api_key,
        'resource': 'malware_hash'  # Список хешей, которые необходимо проверить
    }
    
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            return extract_signatures(data)  # Обработка полученных данных
        else:
            print(f"[ERROR] Ошибка API: {response.status_code}")
            return []
    except Exception as e:
        print(f"[ERROR] Не удалось подключиться к API: {e}")
        return []

# Извлечение сигнатур из данных API
def extract_signatures(data):
    signatures = []
    if 'scans' in data:
        for scan in data['scans']:
            if data['scans'][scan]['detected']:
                signatures.append(data['md5'])  # Добавляем хеш вируса в список
    return signatures

# Обновление базы данных новыми сигнатурами
def update_signatures_in_db(signatures):
    conn = connect_db()
    if conn is None:
        return
    
    try:
        with conn.cursor() as cur:
            for signature in signatures:
                cur.execute("""
                    INSERT INTO signatures (signature)
                    VALUES (%s)
                    ON CONFLICT (signature) DO NOTHING;
                """, (signature,))
        conn.commit()
        print(f"[INFO] Обновлено {len(signatures)} сигнатур в базе данных.")
    except Exception as e:
        print(f"[ERROR] Ошибка при обновлении сигнатур: {e}")
    finally:
        conn.close()

# Обновление базы сигнатур через API
def update_signatures():
    print("[INFO] Обновление сигнатур через API...")
    signatures = fetch_signatures_from_api()  # Получаем сигнатуры
    if signatures:
        update_signatures_in_db(signatures)  # Обновляем базу данных
    else:
        print("[INFO] Нет новых сигнатур для обновления.")

# Функция для GUI кнопки "Update"
def update_database():
    update_signatures()  # Запускаем обновление базы через API
    messagebox.showinfo("Update", "База сигнатур успешно обновлена.")

# Планировщик обновления каждые 24 часа
schedule.every(24).hours.do(update_signatures)

# Основной цикл обновления
def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

# GUI Функции для работы кнопок
def choose_directory():
    directory = filedialog.askdirectory()
    if directory:
        scan_files(directory)

# Другие функции (choose_directory, update_database, show_settings, show_support) остаются без изменений...

def show_settings():
    clear_content()
    settings_label = tk.Label(main_content, text="Настройки", font=("Arial", 18), bg="white")
    settings_label.pack(pady=20)

    # Пример полей для ввода
    db_label = tk.Label(main_content, text="Настройки базы данных:", font=("Arial", 14), bg="white")
    db_label.pack(pady=10)

    db_name_label = tk.Label(main_content, text="Имя базы данных:", bg="white")
    db_name_label.pack()
    db_name_entry = tk.Entry(main_content)
    db_name_entry.pack()

    user_label = tk.Label(main_content, text="Имя пользователя:", bg="white")
    user_label.pack()
    user_entry = tk.Entry(main_content)
    user_entry.pack()

    password_label = tk.Label(main_content, text="Пароль:", bg="white")
    password_label.pack()
    password_entry = tk.Entry(main_content, show="*")
    password_entry.pack()

    host_label = tk.Label(main_content, text="Хост:", bg="white")
    host_label.pack()
    host_entry = tk.Entry(main_content)
    host_entry.pack()

    port_label = tk.Label(main_content, text="Порт:", bg="white")
    port_label.pack()
    port_entry = tk.Entry(main_content)
    port_entry.pack()

    save_button = tk.Button(main_content, text="Сохранить настройки", bg="#f0f0f0", command=lambda: messagebox.showinfo("Настройки", "Настройки сохранены"))
    save_button.pack(pady=20)

def show_support():
    clear_content()
    support_label = tk.Label(main_content, text="Поддержка SG - Antivirus", font=("Arial", 18), bg="white")
    support_label.pack(pady=20)

    contact_label = tk.Label(main_content, text="Для технической поддержки обратитесь:", bg="white")
    contact_label.pack()

    email_label = tk.Label(main_content, text="Email: support@secguard.com", font=("Arial", 12), bg="white")
    email_label.pack(pady=10)

    phone_label = tk.Label(main_content, text="Телефон: +7 (747) 483-34-72", font=("Arial", 12), bg="white")
    phone_label.pack(pady=10)

def show_home():
    clear_content()

    # Загрузка фонового изображения
    bg_image_path = "/home/kali/Desktop/antivirus/background_image.png"  
    bg_img = Image.open(bg_image_path)
    bg_photo = ImageTk.PhotoImage(bg_img)
    
    

    # Создание метки для фонового изображения
    bg_label = tk.Label(main_content, image=bg_photo)
    bg_label.image = bg_photo  # Сохранение ссылки на изображение
    bg_label.place(relwidth=1, relheight=1)  

    # Добавление приветственного текста
    home_label = tk.Label(main_content, text="Добро пожаловать в Security Guard - Antivirus", font=("Arial", 18), bg="white")
    home_label.pack(pady=20)

def clear_content():
    # Удаление всех виджетов с основного контента
    for widget in main_content.winfo_children():
        widget.destroy()
def on_resize(event):
    bg_label.place(relwidth=1, relheight=1)
# Создание GUI
root = tk.Tk()
root.title("Security Guard - Antivirus")
root.geometry("800x500")

# Боковая панель
sidebar = tk.Frame(root, width=200, bg="#e0e0e0")
sidebar.pack(side="left", fill="y")

# Основная область
main_content = tk.Frame(root, bg="white")
main_content.pack(side="right", expand=True, fill="both")

# Добавление кнопок на боковую панель
logo = tk.Label(sidebar, text="Security Guard", bg="#e0e0e0", font=("Arial", 16, "bold"))
logo.pack(pady=20)

# Обновление кнопок
button_style = {'width': 20, 'bg': '#f0f0f0'}

home_button = tk.Button(sidebar, text="Home", command=show_home, **button_style)
home_button.pack(pady=10)

scan_button = tk.Button(sidebar, text="File Scan", command=choose_directory, **button_style)
scan_button.pack(pady=10)

update_button = tk.Button(sidebar, text="Update Signatures", command=update_database, **button_style)
update_button.pack(pady=10)

settings_button = tk.Button(sidebar, text="Settings", command=show_settings, **button_style)
settings_button.pack(pady=10)

support_button = tk.Button(sidebar, text="Support", command=show_support, **button_style)
support_button.pack(pady=10)

root.bind("<Configure>", on_resize)
# Отображение начального экрана
show_home()

# Запуск основного цикла приложения
root.mainloop()
