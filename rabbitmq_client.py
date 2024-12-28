import psycopg2
from datetime import datetime
from tkinter import messagebox
import json
import pika

# Функция для подключения к RabbitMQ
class RabbitMQClient:
    def __init__(self, host='localhost', queue='antivirus_queue'):
        self.host = host
        self.queue = queue
        self.connection = None
        self.channel = None

    def connect(self):
        """Подключение к RabbitMQ."""
        try:
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.host))
            self.channel = self.connection.channel()
            self.channel.queue_declare(queue=self.queue, durable=True)
            print(f"Подключено к RabbitMQ. Очередь: {self.queue}")
        except Exception as e:
            print(f"Ошибка подключения к RabbitMQ: {e}")

    def send_message(self, message):
        """Отправка сообщения в очередь."""
        if not self.channel:
            print("Ошибка: отсутствует подключение к каналу RabbitMQ.")
            return
        try:
            self.channel.basic_publish(
                exchange='',
                routing_key=self.queue,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2  # Устойчивое сообщение
                )
            )
            print(f"Сообщение отправлено: {message}")
        except Exception as e:
            print(f"Ошибка отправки сообщения: {e}")

    #def close(self):
        """Закрытие подключения."""
     #   if self.connection:
      #      self.connection.close()
       #     print("Соединение с RabbitMQ закрыто.")

# Функция для подключения к базе данных
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

# Функция для добавления файла в карантин и отправки сообщения в RabbitMQ
def get_quarantine_logs():
    conn = connect_db()
    if conn is None:
        return []

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT file_path, date_quarantined, status FROM quarantine WHERE status = 'Карантин';")
            # Извлекаем все записи из таблицы quarantine
            logs = cur.fetchall()
            return logs
    except Exception as e:
        print(f"Ошибка при чтении данных: {e}")
        return []
    finally:
        conn.close()

def send_logs_to_rabbitmq():
    # Получаем логи карантина из базы данных
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
    rabbitmq.close()

# Вызов функции для отправки логов в RabbitMQ
send_logs_to_rabbitmq()

