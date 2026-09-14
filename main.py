from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ipaddress
import time
import sys
from datetime import datetime
 
VERSION = "v0.6.0"
BOX_WIDTH = 44  # ширина рамки по умолчанию, подстраивается под контент
 
SERVICES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP Submission", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
    27017: "MongoDB",
}
 
 
# ---------------------------------------------------------------------------
# Вспомогательные функции отрисовки рамки
# ---------------------------------------------------------------------------
 
def box_line(text="", width=BOX_WIDTH, align="left"):
    """Печатает одну строку внутри рамки с корректным padding'ом,
    даже если text длиннее исходной ширины — рамка расширится."""
    inner_width = max(width - 4, len(text))
    if align == "left":
        content = text.ljust(inner_width)
    else:
        content = text.center(inner_width)
    print(f"│ {content} │")
 
 
def box_top(title, subtitle, width=BOX_WIDTH):
    print("╭" + "─" * (width - 2) + "╮")
    box_line(f"{title:<20}{subtitle:>{width-24}}", width)
    print("├" + "─" * (width - 2) + "┤")
 
 
def box_sep(width=BOX_WIDTH):
    print("├" + "─" * (width - 2) + "┤")
 
 
def box_bottom(width=BOX_WIDTH):
    print("╰" + "─" * (width - 2) + "╯")
 
 
# ---------------------------------------------------------------------------
# Основная логика сканирования
# ---------------------------------------------------------------------------
 
def resolve_target(raw_target):
    """Принимает IP или доменное имя, возвращает IP-адрес или None."""
    raw_target = raw_target.strip()
    try:
        ipaddress.ip_address(raw_target)
        return raw_target
    except ValueError:
        pass
 
    try:
        return socket.gethostbyname(raw_target)
    except socket.gaierror:
        return None
 
 
def grab_banner(sock, timeout=0.5):
    """Пытается прочитать баннер сервиса (необязательно, best-effort)."""
    try:
        sock.settimeout(timeout)
        data = sock.recv(64)
        return data.decode(errors="ignore").strip().replace("\n", " ")[:30]
    except Exception:
        return ""
 
 
def check_port(target, port, timeout, do_banner):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result != 0:
                return None
 
            service = SERVICES.get(port, "unknown")
            banner = grab_banner(sock) if do_banner else ""
            return port, service, banner
    except OSError:
        # временная сетевая ошибка на конкретном порту — не валим всё сканирование
        return None
 
 
def ask_int(prompt, default=None):
    raw = input(prompt).strip()
    if raw == "" and default is not None:
        return default
    return int(raw)
 
 
def scan_ports():
    box_top("NETSCOUT", VERSION)
    box_line("TARGET")
    target_raw = input("  └─ ")
 
    ip = resolve_target(target_raw)
    if ip is None:
        print(f"Ошибка: не удалось разрешить «{target_raw}» (не IP и не резолвится как домен).")
        return
    if ip != target_raw:
        print(f"  (разрешено в {ip})")
 
    box_sep()
    box_line("SCAN CONFIGURATION")
    box_line("  ├─ TCP")
 
    try:
        port_start = ask_int("  ├─ Start port [1]: ", default=1)
        port_end = ask_int("  ├─ End port [1024]: ", default=1024)
    except ValueError:
        print("Ошибка: порты должны быть целыми числами.")
        return
 
    if port_start > port_end:
        port_start, port_end = port_end, port_start
        print("  (диапазон портов был перевёрнут — поменял местами)")
 
    if not (1 <= port_start <= port_end <= 65535):
        print("Ошибка: некорректный диапазон портов (допустимо 1–65535).")
        return
 
    try:
        timeout = float(input("  ├─ Timeout, сек [1.0]: ").strip() or 1.0)
    except ValueError:
        timeout = 1.0
 
    do_banner = input("  ├─ Пытаться получить баннер службы? [y/N]: ").strip().lower() == "y"
 
    total_ports = port_end - port_start + 1
    max_workers = min(200, max(30, total_ports))
 
    box_sep()
    box_line("SCAN RESULTS")
 
    open_ports_list = []
    start_time = time.time()
 
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_port, ip, port, timeout, do_banner): port
                for port in range(port_start, port_end + 1)
            }
 
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue
 
                port, service, banner = result
                open_ports_list.append(port)
 
                label = f"{port}/tcp"
                line = f"● {label:<10}{service}"
                if banner:
                    line += f"  [{banner}]"
                box_line(line)
 
    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем (Ctrl+C).")
 
    end_time = time.time()
    scan_time = end_time - start_time
    open_ports_list.sort()
 
    if not open_ports_list:
        box_line("  (открытых портов не найдено)")
 
    box_sep()
    box_line("SUMMARY")
    box_line(f"  Target             {ip}")
    box_line(f"  Open ports         {len(open_ports_list)}")
    box_line(f"  Scan duration      {scan_time:.2f}s")
    box_bottom()
 
    if open_ports_list and input("\nСохранить результаты в файл? [y/N]: ").strip().lower() == "y":
        save_results(ip, open_ports_list, scan_time)
 
 
def save_results(target, open_ports, scan_time):
    filename = f"netscout_{target.replace('.', '_')}_{datetime.now():%Y%m%d_%H%M%S}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"NetScout {VERSION} — отчёт сканирования\n")
        f.write(f"Цель: {target}\n")
        f.write(f"Дата: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Длительность: {scan_time:.2f}s\n\n")
        f.write("Открытые порты:\n")
        for port in open_ports:
            service = SERVICES.get(port, "unknown")
            f.write(f"  {port}/tcp\t{service}\n")
    print(f"Сохранено в {filename}")
 
 
# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------
 
def main():
    while True:
        print()
        box_top("NETSCOUT", VERSION)
        box_line("[1] Сканировать порты")
        box_line("[2] Выход")
        box_bottom()
 
        choice = input("Выберите действие: ").strip()
 
        if choice == "1":
            try:
                scan_ports()
            except KeyboardInterrupt:
                print("\nПрервано.")
        elif choice == "2":
            print("Выход из NetScout...")
            sys.exit(0)
        else:
            print("Ошибка: неизвестный пункт меню.")
 
 
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nЗавершение работы.")
        sys.exit(0)