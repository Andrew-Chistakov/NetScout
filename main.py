from concurrent.futures import ThreadPoolExecutor # для многопоточного сканирования
import socket # для работы с сетевыми сокетами
import ipaddress # для проверки корректности IP-адреса
import time # для измерения времени сканирования


# документация продукта
print("NetScout")
print("Network Security Scanner")
print("Version: 0.4")

# получение IP-адреса для сканирования
target = input("Введите IP-адрес: ")

# проверка корректности введенного IP-адреса
try:
    ipaddress.ip_address(target)
except ValueError:
    print("Ошибка: Некорректный IP-адрес.")
    exit()

# получение диапазона портов для сканирования
port_start = input("Введите начальный порт: ")
port_end = input("Введите конечный порт: ")

# проверка корректности введенного диапазона портов
try:
    port_start = int(port_start)
    port_end = int(port_end)

    if not (1 <= port_start <= port_end <= 65535):
        print("Ошибка: Некорректный диапазон портов.")
        exit()
except ValueError:
    print("Ошибка: Введены некорректные данные для диапазона портов.")
    exit()

# словарь служб
services = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy / Alternative HTTP",
    8443: "Alternative HTTPS",
    27017: "MongoDB"
}

# функция для проверки порта
def check_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    result = sock.connect_ex((target, port))

    if result == 0:
        service = services.get(port, "Неизвестная служба")
        sock.close()
        return port, service

    sock.close()
    return None

# счетчик,список открытых портов и список задач для многопоточного сканирования
open_ports = 0 
open_ports_list = []
futures = []

# запуск таймера для измерения времени сканирования
start_time = time.time()

# сканирование портов
with ThreadPoolExecutor(max_workers=10) as executor:

    for port in range(port_start, port_end + 1):
        future = executor.submit(check_port, target, port)
        futures.append(future)

for future in futures:
    result = future.result()

    if result is not None:
        port, service = result
        open_ports += 1
        open_ports_list.append(port)
        print(f"[+] Порт {port} открыт — {service}")

# завершение таймера и расчет времени сканирования
end_time = time.time()
scan_time = end_time - start_time

# результаты сканирования
print("Сканирование завершено.")
print(f"Количество открытых портов: {open_ports}")
print(f"Открытые порты: {open_ports_list}")
print(f"Время сканирования: {scan_time:.2f} секунд")