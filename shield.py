import pika
import json

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

    def consume_messages(self, callback):
        """Обработка сообщений из очереди."""
        if not self.channel:
            print("Ошибка: отсутствует подключение к каналу RabbitMQ.")
            return
        try:
            def wrapper(ch, method, properties, body):
                message = json.loads(body)
                callback(message)
                ch.basic_ack(delivery_tag=method.delivery_tag)

            self.channel.basic_consume(queue=self.queue, on_message_callback=wrapper)
            print("Ожидание сообщений. Нажмите Ctrl+C для завершения.")
            self.channel.start_consuming()
        except Exception as e:
            print(f"Ошибка при обработке сообщений: {e}")

    def close(self):
        """Закрытие подключения."""
        if self.connection:
            self.connection.close()
            print("Соединение с RabbitMQ закрыто.")
