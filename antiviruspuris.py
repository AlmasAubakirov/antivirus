import os
import shutil
import psycopg2
import hashlib
import requests
import schedule
import time
from api import update
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import psutil
from matplotlib.animation import FuncAnimation
from rabbitmq_client import RabbitMQClient
import time

ani = None
# Подключение к базе данных
def connect_db():
    try:
        conn = psycopg2.connect(
            dbname='antivirus_db',
            user='postgres',
            password='123456P@$$',
            host='localhost',
            port='5432'
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
            signatures = cur.fetchall()
            return [sig[0] for sig in signatures]
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
    quarantine_dir = "Quarantine"
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
        status = 'Quarantine'
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
    progress_bar = ttk.Progressbar(main_content, orient="horizontal", mode="determinate")
    progress_bar.pack(pady=20, fill='x')
    
    total_files = sum([len(files) for _, _, files in os.walk(directory)])
    progress_bar["maximum"] = total_files
    

    for root, _, files in os.walk(directory):
        for file in files:
            total_files_scanned += 1
            file_path = os.path.join(root, file)
            if is_infected(file_path):
                quarantine_file(file_path)
                threats_found += 1
            progress_bar["value"] = total_files_scanned
            root.update_idletasks()
    
   
    while True:
        try:
            a = {i: psutil.Process(i).name() for i in psutil.pids()}
            for i in a:
                if 'virus.exe' in a[i]:
                    print(f"ALERT: PID={i}")
                    psutil.Process(i).terminate()
                    threats_found += 1
            time.sleep(5)
        except:
            pass
    end_time = datetime.now()
    action_taken = "Файлы перемещены в карантин"
    
    insert_scan_history(start_time, end_time, total_files_scanned, threats_found, action_taken)
    progress_bar.destroy()
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


# Обновление базы сигнатур через API
def update_signatures():
    url = 'https://mb-api.abuse.ch/api/v1/'
    params = {
        'api_key': '0a334b04a09f6d0010e09f2789a9958d',
        'action': 'get_info'
    }
    print("[INFO] Обновление сигнатур через API...")
    try:
        response = requests.post(url, data=params)
        update()
        data = response.json()
        if response.status_code == 200 and data.get('success'):
            signatures = extract_signatures(data)
            if signatures:
                update_signatures_in_db(signatures)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Ошибка API: {e}")

# Функция для GUI кнопки "Update"
def update_database():
    update_signatures()
    messagebox.showinfo("Update", "База сигнатур успешно обновлена.")

# Функция для мониторинга процессов
def monitor_processes():
    clear_content()	
    process_label = tk.Label(main_content, text="Активные процессы", font=("Arial", 18), bg="#3a4750")
    process_label.pack(pady=10)
    process_text = scrolledtext.ScrolledText(main_content, width=90, height=20, wrap=tk.WORD)
    process_text.pack(pady=10)
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            process_info = f"PID: {proc.info['pid']}, Имя: {proc.info['name']}, Пользователь: {proc.info['username']}"
            process_text.insert(tk.END, process_info + "\n")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
def get_quarantine_logs():
    conn = connect_db()
    if conn is None:
        return []

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT file_path, date_quarantined, status FROM quarantine WHERE status = 'active';")
            logs = cur.fetchall()
            
            return logs
    except Exception as e:
        print(f"Ошибка при чтении данных: {e}")
        return []
    finally:
        conn.close()

def send_logs_to_rabbitmq():
    logs = get_quarantine_logs()

    if not logs:
        print("Нет данных для отправки.")
        return

    # Инициализируем RabbitMQ клиент
    
    
    rabbitmq = RabbitMQClient()
    rabbitmq.connect()

    # Отправляем каждый лог в очередь RabbitMQ
    for log in logs:
        file_path, date_quarantined, status = log
        message_to_send = {
            "file_path": file_path,
            "date_quarantined": date_quarantined.isoformat(),
            "status": status,
            "scanner": "antivirus"
        }
        rabbitmq.send_message(message_to_send)

    # Закрываем соединение с RabbitMQ
    
    
send_logs_to_rabbitmq()
    

# Функция для отображения главной страницы
def show_home():
    clear_content()

    # Загрузка фонового изображения
    bg_image_path = "/home/kali/Desktop/antivirus/background_image.png"

    # Создаем объект изображения
    bg_img = Image.open(bg_image_path)

    # Получаем текущие размеры окна
    window_width = root.winfo_width()
    window_height = root.winfo_height()

    # Масштабируем изображение до размеров окна
    bg_img = bg_img.resize((window_width, window_height), Image.Resampling.LANCZOS)
    bg_photo = ImageTk.PhotoImage(bg_img)

    # Создание метки для фонового изображения
    bg_label = tk.Label(main_content, image=bg_photo)
    bg_label.image = bg_photo  # Сохранение ссылки на изображение
    bg_label.place(relwidth=1, relheight=1)  # Растягиваем на всю ширину и высоту

    # Добавление приветственного текста
    home_label = tk.Label(
        main_content,
        text="Добро пожаловать в Security Guard - Antivirus",
        font=("Arial", 18),
        bg="#3a4750",
        fg="white",
    )
    
    home_label.pack(pady=20)
 
    shield_image_path = "/home/kali/Desktop/antivirus/1.jpg"  # Путь к изображению щита
    shield_img = Image.open(shield_image_path).convert("RGBA")
    shield_img = shield_img.resize((100, 100), Image.Resampling.LANCZOS)  # Изменяем размер изображения
    shield_photo = ImageTk.PhotoImage(shield_img)

    shield_label = tk.Label(main_content, image=shield_photo, bg="#3a4750")
    shield_label.image = shield_photo  # Сохранение ссылки на изображение
    shield_label.pack(pady=(10, 0))  # Добавление отступа сверху, без отступа снизу

    protected_text_label = tk.Label(
        main_content,
        text="Вы защищены",
        font=("Arial", 24),
        bg="#3a4750",
        fg="white",
    )
    protected_text_label.pack(pady=(0, 20))  # Добавление отступа снизу

    # Создаем контейнер для графиков
    graph_frame = tk.Frame(main_content, bg="#3a4750")
    graph_frame.pack(fill="x",side="bottom", expand=False, pady=(0,10))

    # Инициализация данных
    time_data = ["1PM", "2PM", "3PM", "4PM", "5PM", "6PM", "7PM"]
    energy_data = [50] * len(time_data)  # Потребление процессора

    # Создание первого графика (потребление электроэнергии устройства / загрузка CPU)
    fig1, ax1 = plt.subplots(figsize=(4, 2), dpi=100, facecolor='none')
    line, = ax1.plot(time_data, energy_data, marker="o", color="black")
    
    ax1.set_title("CPU (%)")
    ax1.set_xlabel("Time")
    ax1.set_ylabel("Use (%)")
    ax1.set_facecolor('none')
    ax1.set_ylim(0, 100)
    fig1.patch.set_alpha(0.0)

    # Встраивание графика в Tkinter
    chart1 = FigureCanvasTkAgg(fig1, graph_frame)
    chart1.get_tk_widget().pack(side="left", expand=True)

    # Создание второго графика (использование ОЗУ)
    fig2, ax2 = plt.subplots(figsize=(4, 2), dpi=100, facecolor='none')
    ram_usage = psutil.virtual_memory()
    sizes = [ram_usage.used / (1024 ** 3), ram_usage.available / (1024 ** 3)]
    labels = ["Using", "Free"]
    colors = ["red", "green"]
    fig2.patch.set_alpha(0.0)
    pie = ax2.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90, colors=colors)
    ax2.set_title("Using RAM")
    ax2.set_facecolor('none')
    

    # Встраивание диаграммы в Tkinter
    chart2 = FigureCanvasTkAgg(fig2, graph_frame)
    chart2.get_tk_widget().pack(side="left", expand=True)

    # Функция для обновления данных
    def update_data():
        # Обновление данных для первого графика
        cpu_usage = psutil.cpu_percent(interval=0.1)  # Загрузка процессора
        energy_data.pop(0)
        energy_data.append(cpu_usage)
        line.set_ydata(energy_data)
        fig1.canvas.draw()

        # Обновление данных для второго графика
        ram_usage = psutil.virtual_memory()
        sizes = [ram_usage.used / (1024 ** 3), ram_usage.available / (1024 ** 3)]
        for wedge, size in zip(pie[0], sizes):
            wedge.set_theta1(size)
        fig2.canvas.draw()

        # Запланировать следующий апдейт
        main_content.after(1000, update_data)

    # Запуск обновления данных
    update_data()

# Функция для обновления интерфейса при изменении размера окна
def on_resize(event):
    show_home()
    
# Функция для мониторинга сетевой активности
def monitor_network():
    clear_content()
    network_label = tk.Label(main_content, text="Сетевая активность", font=("Arial", 18), bg="#3a4750")
    network_label.pack(pady=10)
    network_text = scrolledtext.ScrolledText(main_content, width=90, height=20, wrap=tk.WORD)
    network_text.pack(pady=10)
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            try:
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                connection_info = f"Локальный адрес: {local_address}, Удаленный адрес: {remote_address}, Статус: {conn.status}"
                network_text.insert(tk.END, connection_info + "\n")
            except Exception as e:
                network_text.insert(tk.END, f"Ошибка получения данных: {e}\n")

def clear_content():
    # Удаление всех виджетов с основного контента
    for widget in main_content.winfo_children():
        widget.destroy()

def show_support():
    clear_content()
    support_label = tk.Label(main_content, text="Поддержка SG - Antivirus", font=("Arial", 18), bg="#3a4750")
    support_label.pack(pady=20)

    contact_label = tk.Label(main_content, text="Для технической поддержки обратитесь:", bg="#3a4750")
    contact_label.pack()

    email_label = tk.Label(main_content, text="Email: support@secguard.com", font=("Arial", 12), bg="#3a4750")
    email_label.pack(pady=10)

    phone_label = tk.Label(main_content, text="Телефон: +7 (747) 483-34-72", font=("Arial", 12), bg="#3a4750")
    phone_label.pack(pady=10)

def show_settings():
    clear_content()
    settings_label = tk.Label(main_content, text="Настройки", font=("Arial", 18), bg="#3a4750")
    settings_label.pack(pady=20)

    db_label = tk.Label(main_content, text="Настройки базы данных:", font=("Arial", 14), bg="#3a4750")
    db_label.pack(pady=10)

    db_name_label = tk.Label(main_content, text="Имя базы данных:", bg="#3a4750")
    db_name_label.pack()
    db_name_entry = tk.Entry(main_content)
    db_name_entry.pack()

    user_label = tk.Label(main_content, text="Имя пользователя:", bg="#3a4750")
    user_label.pack()
    user_entry = tk.Entry(main_content)
    user_entry.pack()

    password_label = tk.Label(main_content, text="Пароль:", bg="#3a4750")
    password_label.pack()
    password_entry = tk.Entry(main_content, show="*")
    password_entry.pack()

    host_label = tk.Label(main_content, text="Хост:", bg="#3a4750")
    host_label.pack()
    host_entry = tk.Entry(main_content)
    host_entry.pack()

    port_label = tk.Label(main_content, text="Порт:", bg="#3a4750")
    port_label.pack()
    port_entry = tk.Entry(main_content)
    port_entry.pack()

    save_button = tk.Button(main_content, text="Сохранить настройки", bg="#f0f0f0", command=lambda: messagebox.showinfo("Настройки", "Настройки сохранены"))
    save_button.pack(pady=20)


root = tk.Tk()
root.title("Security Guard - Antivirus")
root.geometry("800x500")

# Боковая панель с Canvas для прозрачности
sidebar = tk.Canvas(root, width=210, bg="#303841", highlightthickness=0)
sidebar.pack(side="left", fill="y")

# Основная область с Canvas для основного содержимого
main_content = tk.Canvas(root, bg="#3a4750", highlightthickness=0)
main_content.pack(side="right", expand=True, fill="both")

# Логотип и заголовок приложения
sidebar.create_text(100, 40, text="Security Guard", font=("Arial", 20, "bold"), fill="lightblue")



# Кнопки на боковой панели
buttons = [
    ("Home", show_home),
    ("File Scan", lambda: filedialog.askdirectory()),
    ("Update Signatures", update_database),
    ("Process Monitor", monitor_processes),
    ("Network Monitor", monitor_network),
    ("Settings", show_settings),
    ("Support", show_support)
]

# Создание кнопок с использованием Canvas и настройкой полупрозрачного фона
y_pos = 100
for (text, command) in buttons:
    button = tk.Button(root, text=text, width=20, font=("Arial", 12), command=command, 
                       bg="#3a4750", fg="white", activebackground="#465661", relief="flat")
    sidebar.create_window(100, y_pos, window=button)
    y_pos += 50
# Функция для очистки контента
def clear_content():
    for widget in main_content.winfo_children():
        widget.destroy()

show_home()
# Обработчик изменения размера окна
root.after(100, show_home)


# Запуск основного цикла приложения
root.mainloop()
