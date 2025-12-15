import socket
import threading
import logging
import argparse
from datetime import datetime
import sys
from collections import defaultdict
import time
import os 
import random


MAX_CONNECTIONS_PER_IP = 1000 
HIGH_PORTS_OFFSET = 10000  

# Статистика
stats = {
    'total_connections': 0,
    'connections_by_ip': defaultdict(int),
    'connections_by_port': defaultdict(int),
    'scan_types': defaultdict(int)
}

# Блокировка для потокобезопасности
stats_lock = threading.Lock()

# Логирование
def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

# Обнаружение сканирования
def detect_scan_type(data, port):
    # Определение типа сканирования
    if not data:
        return "NULL_SCAN"
    
    try:
        data_str = data.decode('latin-1', errors='ignore')
    except:
        return "BINARY_DATA"
    
    # SSH сканирование
    if data.startswith(b'SSH-') or 'SSH' in data_str.upper():
        return "SSH_SCAN"
    
    # HTTP сканирование
    if b'GET' in data or b'POST' in data or b'HEAD' in data or b'HTTP' in data:
        return "HTTP_SCAN"
    
    # SSL/TLS сканирование
    if data.startswith(b'\x16\x03'):
        return "SSL_SCAN"
    
    # FTP сканирование
    if data.startswith(b'USER') or data.startswith(b'PASS') or 'FTP' in data_str.upper():
        return "FTP_SCAN"
    
    return "UNKNOWN_SCAN"

# Ответы
def get_response_for_port(port, scan_type, data):
    # Генерация ответа
    
    # Базовые ответы для разных портов
    responses = {
        # Низкие порты (требуют root)
        22: b'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n',
        80: b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome!</h1></body></html>\r\n',
        443: b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Secure Portal</h1></body></html>\r\n',
        
        # Высокие порты 
        2222: b'SSH-2.0-OpenSSH_8.4p1 Debian 5+deb11u5\r\n',
        12222: b'SSH-2.0-OpenSSH_8.4p1 Debian 5+deb11u5\r\n',
        
        8080: b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Development Server</h1></body></html>\r\n',
        18080: b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Development Server</h1></body></html>\r\n',
        
        8443: b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body><h1>HTTPS Service</h1></body></html>\r\n',
        18443: b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body><h1>HTTPS Service</h1></body></html>\r\n',
    }
    
    # Специальные ответы для SSL
    if scan_type == "SSL_SCAN":
        if data.startswith(b'\x16\x03'):
            # Простой SSL Server Hello
            return b'\x16\x03\x03\x00\x31\x02\x00\x00\x2d\x03\x03' + os.urandom(32) + b'\x00\x00\x00'
    
    return responses.get(port, b'CONNECTION ESTABLISHED\r\n')

# Обработка подключения
def handle_connection(client_socket, client_address, port):
    # Обработка одного подключения
    client_ip = client_address[0]
    
    try:
        
        # Обновление статистики
        with stats_lock:
            stats['connections_by_ip'][client_ip] += 1
            stats['total_connections'] += 1
            stats['connections_by_port'][port] += 1
        
        # Получение данных
        client_socket.settimeout(3.0)
        data = client_socket.recv(1024)
        
        # Определение типа сканирования
        scan_type = detect_scan_type(data, port)
        with stats_lock:
            stats['scan_types'][scan_type] += 1
        
        # Логирование
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"{client_ip}:{client_address[1]} -> PORT:{port} | {scan_type}"
        
        logging.info(log_message)
        print(f"[{timestamp}] {log_message}")
        
        # Отправка ответа
        response = get_response_for_port(port, scan_type, data)
        client_socket.send(response)
        
        # Небольшая задержка для сбора данных
        if scan_type in ["SSH_SCAN", "FTP_SCAN"]:
            time.sleep(0.5)
        
    except socket.timeout:
        pass
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        client_socket.close()

# Запуск Honeypot
def start_honeypot(host, port):
    # Запуск honeypot с автоподбором порта
    original_port = port
    current_port = port
    
    # Если порт < 1024, используем высокий порт
    if port < 1024:
        current_port = port + HIGH_PORTS_OFFSET
        print(f"[!] Port {port} requires root. Using {current_port} instead.")
    
    # Пробуем разные порты если занят
    for attempt in range(3):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, current_port))
            server_socket.listen(10)
            
            if current_port != original_port:
                print(f"[*] Port {original_port} -> {current_port}")
            
            print(f"[*] Listening on {host}:{current_port}")
            logging.info(f"Honeypot started on port {current_port} (original: {original_port})")
            
            while True:
                client_socket, client_address = server_socket.accept()
                thread = threading.Thread(
                    target=handle_connection,
                    args=(client_socket, client_address, original_port),  
                    # Логируем оригинальный порт
                    daemon=True
                )
                thread.start()
                
            break  # Успешно запустились
            
        except OSError as e:
            if "Address already in use" in str(e) and attempt < 2:
                current_port += random.randint(100, 1000)
                print(f"[!] Port busy. Trying {current_port}...")
                continue
            else:
                print(f"[ERROR] Cannot bind to port {original_port}: {e}")
                logging.error(f"Failed to start on port {original_port}: {e}")
                break
        except Exception as e:
            print(f"[ERROR] {e}")
            break

# Статистика
def print_stats():
    # Вывод статистики
    with stats_lock:
        print("\n" + "="*60)
        print("СТАТИСТИКА HONEYPOT")
        print("="*60)
        print(f"Всего подключений: {stats['total_connections']}")
        print(f"Уникальных IP: {len(stats['connections_by_ip'])}")
        
        print("\nПодключения по портам:")
        for port, count in sorted(stats['connections_by_port'].items()):
            print(f"  Порт {port}: {count}")
        
        print("\nТипы сканирования:")
        for scan_type, count in sorted(stats['scan_types'].items()):
            print(f"  {scan_type}: {count}")
        
        print("\nТоп 3 IP-адреса:")
        for ip, count in sorted(stats['connections_by_ip'].items(), key=lambda x: x[1], reverse=True)[:3]:
            print(f"  {ip}: {count} подключений")
        
        print("="*60)

# Главная функция
def main():
    parser = argparse.ArgumentParser(description='Honeypot для лабораторной работы №4')
    parser.add_argument('--host', default='0.0.0.0', help='Хост для прослушивания')
    parser.add_argument('--ports', default='12222,18080,18443', 
                       help='Порты (рекомендуем высокие: 12222,18080,18443)')
    parser.add_argument('--log', default='lab4_honeypot.log', help='Файл логов')
    parser.add_argument('--stats-interval', type=int, default=30, 
                       help='Интервал вывода статистики в секундах')
    
    args = parser.parse_args()
    
    # Настройка логирования
    setup_logging(args.log)
    
    # Парсинг портов
    ports = []
    for port_str in args.ports.split(','):
        ports.append(int(port_str.strip()))
    
    # Информация о запуске
    print("="*60)
    print("ЛАБОРАТОРНАЯ РАБОТА №4 - HONEYPOT")
    print("="*60)
    print(f"Хост: {args.host}")
    print(f"Порты: {ports}")
    print(f"Лог-файл: {args.log}")
    print(f"Макс. подключений с IP: {MAX_CONNECTIONS_PER_IP}")
    print("="*60)
    print("[*] Запуск honeypot... Для остановки Ctrl+C")
    print("[*] Для тестирования используйте: nmap -sV -A -p [порты] 127.0.0.1")
    print("="*60)
    
    # Запуск honeypot на каждом порту
    threads = []
    for port in ports:
        thread = threading.Thread(
            target=start_honeypot,
            args=(args.host, port),
            daemon=True
        )
        thread.start()
        threads.append(thread)
    
    # Периодический вывод статистики
    last_stats_time = time.time()
    try:
        while True:
            time.sleep(1)
            current_time = time.time()
            if current_time - last_stats_time >= args.stats_interval:
                print_stats()
                last_stats_time = current_time
                
    except KeyboardInterrupt:
        print("\n[*] Остановка honeypot...")
        print_stats()
        logging.info("Honeypot остановлен пользователем")
        print(f"[*] Логи сохранены в {args.log}")

if __name__ == "__main__":
    main()
