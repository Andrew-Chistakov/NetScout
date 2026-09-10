import socket
import ipaddress
import time

# документация продукта
print("NetScout")
print("Network Security Scanner")
print("Version: 0.2")

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

# счетчик и список открытых портов
open_ports = 0 
open_ports_list = []

# запуск таймера для измерения времени сканирования
start_time = time.time()

# сканирование портов
for port in range(port_start, port_end + 1):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    result = sock.connect_ex((target, port))

    if result == 0:
        print(f"[+] Порт {port} открыт")
        open_ports += 1
        open_ports_list.append(port)
    sock.close()

# завершение таймера и расчет времени сканирования
end_time = time.time()
scan_time = end_time - start_time

# результаты сканирования
print("Сканирование завершено.")
print(f"Количество открытых портов: {open_ports}")
print(f"Открытые порты: {open_ports_list}")
print(f"Время сканирования: {scan_time:.2f} секунд")