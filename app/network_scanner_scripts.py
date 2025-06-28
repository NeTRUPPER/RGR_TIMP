import argparse
import nmap
import dns.resolver
import socket
import os
import subprocess
import requests
from typing import List, Dict, Any

# Проверка, запущен ли скрипт с правами root

def is_root() -> bool:
    return os.geteuid() == 0

# Сканирование открытых портов

def scan_open_ports(target: str, ports: str = "1-65535", privileged: bool = False, fast: bool = False) -> Dict[str, Any]:
    nm = nmap.PortScanner()
    
    # Настройки скорости и интенсивности сканирования
    timing_opts = '-T4' if fast else '-T3'
    min_rate = '--min-rate 1000' if fast else '--min-rate 100'
    parallel = '--min-parallelism 10' if fast else '--min-parallelism 5'
    version_intensity = '--version-intensity 2' if fast else '--version-intensity 4'
    
    # Выбор параметров сканирования в зависимости от прав и режима
    if privileged and is_root():
        if fast:
            scan_args = f'-sS {timing_opts} {min_rate} {parallel} -sV {version_intensity} --max-retries 1'
        else:
            scan_args = f'-sS -sU {timing_opts} {parallel} -sV {version_intensity}'
    else:
        if fast:
            scan_args = f'-sT {timing_opts} {min_rate} {parallel} -sV {version_intensity} --max-retries 1'
        else:
            scan_args = f'-sT {timing_opts} {parallel} -sV {version_intensity}'
    
    try:
        nm.scan(target, ports, arguments=scan_args)
    except nmap.PortScannerError as e:
        return {
            'error': str(e),
            'recommendation': 'Попробуйте запустить с sudo для расширенного сканирования.'
        }
    
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            'state': nm[host].state(),
            'tcp': {},
            'udp': {}
        }
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_data = nm[host][proto][port]
                if port_data['state'] in ['open', 'open|filtered']:
                    results[host][proto][port] = {
                        'state': port_data['state'],
                        'service': port_data.get('name', 'неизвестно'),
                        'product': port_data.get('product', 'неизвестно'),
                        'version': port_data.get('version', 'неизвестно'),
                        'extrainfo': port_data.get('extrainfo', ''),
                        'reason': port_data.get('reason', 'неизвестно')
                    }
    return results

# Пинг хоста

def ping_host(target: str, count: int = 2) -> Dict[str, Any]:
    """Пингует хост и возвращает среднее время отклика."""
    try:
        output = subprocess.check_output([
            'ping', '-c', str(count), '-W', '1', target
        ], stderr=subprocess.STDOUT, universal_newlines=True)
        avg_line = [line for line in output.split('\n') if 'avg' in line or 'rtt' in line]
        if avg_line:
            avg = avg_line[0].split('=')[1].split('/')[1].strip()
            return {'reachable': True, 'avg_ping_ms': avg}
        return {'reachable': True, 'avg_ping_ms': None}
    except subprocess.CalledProcessError:
        return {'reachable': False, 'avg_ping_ms': None}

# Получение баннера HTTP/HTTPS

def get_http_banner(target: str) -> Dict[str, Any]:
    """Пытается получить HTTP баннер с 80 и 443 порта."""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    banners = {}
    for port, proto in [(80, 'http'), (443, 'https')]:
        url = f'{proto}://{target}'
        try:
            resp = requests.get(url, timeout=2, verify=False)
            banners[proto] = {
                'status_code': resp.status_code,
                'server': resp.headers.get('Server', 'Неизвестно'),
                'title': resp.text.split('<title>')[1].split('</title>')[0] if '<title>' in resp.text else ''
            }
        except Exception as e:
            banners[proto] = {'status_code': 'Ошибка', 'server': 'Ошибка', 'title': str(e)}
    return banners

# Проверка наличия IPv6-адреса

def check_ipv6(target: str) -> Dict[str, Any]:
    """Проверяет наличие IPv6-адреса у хоста."""
    try:
        result = socket.getaddrinfo(target, None, socket.AF_INET6)
        if result:
            return {'ipv6': True, 'addresses': [r[4][0] for r in result]}
        else:
            return {'ipv6': False, 'addresses': []}
    except Exception:
        return {'ipv6': False, 'addresses': []}

# Проверка DNS-записей домена или IP

def check_dns(domain_or_ip: str) -> Dict[str, Any]:
    """
    Проверяет:
    - A-запись (основной IP домена)
    - PTR-запись (обратное разрешение IP)
    - MX-записи (почтовые маршруты)
    - NS-записи (делегирование домена)
    - TXT-записи (SPF, DKIM, DMARC)
    - Время отклика DNS
    - Совпадение прямого и обратного разрешения
    """
    resolver = dns.resolver.Resolver()
    result = {'explanation': 'Проверяются основные DNS-записи (A, PTR, MX, NS, TXT), время отклика, SPF/DKIM/DMARC, совпадение прямого и обратного разрешения. Это важно для корректной работы сервисов и безопасности.'}
    try:
        import ipaddress
        is_ip = False
        try:
            ipaddress.ip_address(domain_or_ip)
            is_ip = True
        except:
            pass
        if is_ip:
            try:
                ptr_records = resolver.resolve(domain_or_ip, 'PTR')
                result['PTR'] = [str(r) for r in ptr_records]
            except Exception as e:
                result['PTR'] = f'Ошибка: {e}'
            try:
                hostname = socket.gethostbyaddr(domain_or_ip)[0]
                a_records = resolver.resolve(hostname, 'A')
                result['A'] = [str(r) for r in a_records]
                result['hostname'] = hostname
            except Exception as e:
                result['A'] = f'Ошибка: {e}'
        else:
            try:
                a_records = resolver.resolve(domain_or_ip, 'A')
                result['A'] = [str(r) for r in a_records]
            except Exception as e:
                result['A'] = f'Ошибка: {e}'
            try:
                ip = socket.gethostbyname(domain_or_ip)
                ptr_records = resolver.resolve(ip, 'PTR')
                result['PTR'] = [str(r) for r in ptr_records]
            except Exception as e:
                result['PTR'] = f'Ошибка: {e}'
        try:
            mx_records = resolver.resolve(domain_or_ip, 'MX')
            result['MX'] = [str(r.exchange) for r in mx_records]
        except Exception as e:
            result['MX'] = f'Ошибка: {e}'
        try:
            ns_records = resolver.resolve(domain_or_ip, 'NS')
            result['NS'] = [str(r) for r in ns_records]
        except Exception as e:
            result['NS'] = f'Ошибка: {e}'
        try:
            txt_records = resolver.resolve(domain_or_ip, 'TXT')
            txts = [str(r) for r in txt_records]
            result['TXT'] = txts
            for txt in txts:
                if 'v=spf1' in txt:
                    result['SPF'] = txt
                if 'dkim' in txt.lower():
                    result['DKIM'] = txt
                if 'dmarc' in txt.lower():
                    result['DMARC'] = txt
        except Exception as e:
            result['TXT'] = f'Ошибка: {e}'
        import time
        start_time = time.time()
        try:
            resolver.resolve(domain_or_ip, 'A')
            result['response_time'] = f"{(time.time() - start_time) * 1000:.2f}мс"
        except:
            result['response_time'] = 'таймаут'
        try:
            if 'A' in result and 'PTR' in result and isinstance(result['A'], list) and isinstance(result['PTR'], list):
                a_ip = result['A'][0] if result['A'] else None
                ptr_host = result['PTR'][0] if result['PTR'] else None
                if a_ip and ptr_host and domain_or_ip.rstrip('.') != ptr_host.rstrip('.'):
                    result['A_PTR_mismatch'] = True
        except:
            pass
    except Exception as e:
        result['error'] = str(e)
    return result

def print_dns_info(dns_result: Dict[str, Any]):
    print("\nИнформация о DNS:")
    for key in ['A', 'PTR', 'MX', 'NS', 'TXT', 'SPF', 'DKIM', 'DMARC', 'response_time', 'A_PTR_mismatch']:
        if key in dns_result:
            print(f"  {key}: ")
            val = dns_result[key]
            if isinstance(val, list):
                for v in val:
                    print(f"    - {v}")
            else:
                print(f"    {val}")
    if 'hostname' in dns_result:
        print(f"  Имя хоста: {dns_result['hostname']}")
    if 'error' in dns_result:
        print(f"  Ошибка: {dns_result['error']}")
    print()

# Проверка базовых уязвимостей (открытый Telnet, SMB)

def check_basic_vulns(target: str) -> Dict[str, Any]:
    vulns = {}
    # Telnet (23)
    telnet_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    telnet_sock.settimeout(1)
    try:
        telnet_sock.connect((target, 23))
        vulns['telnet'] = 'открыт'
    except Exception:
        vulns['telnet'] = 'закрыт'
    telnet_sock.close()
    # SMB (445)
    smb_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    smb_sock.settimeout(1)
    try:
        smb_sock.connect((target, 445))
        vulns['smb'] = 'открыт'
    except Exception:
        vulns['smb'] = 'закрыт'
    smb_sock.close()
    return vulns

# Сканирование сети на открытые DNS-серверы

def scan_network_dns_servers(subnet: str, ports: str = "53", privileged: bool = False) -> Dict[str, Any]:
    """Сканирует подсеть на открытые DNS-серверы (53 порт) и делает тестовый DNS-запрос."""
    nm = nmap.PortScanner()
    print(f"\n[DNS-серверы] Сканирование {subnet} на открытый 53 порт...")
    
    # Выбираем параметры сканирования в зависимости от прав
    if privileged and is_root():
        scan_args = '-sU -sT --open -T4 --min-rate 500'
    else:
        scan_args = '-sT --open -T4 --min-rate 500'
    
    try:
        nm.scan(subnet, ports, arguments=scan_args)
    except nmap.PortScannerError as e:
        return {'error': f"Ошибка сканирования: {str(e)}"}
    except Exception as e:
        return {'error': f"Неожиданная ошибка: {str(e)}"}

    try:
        dns_hosts = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    if int(port) == 53 and nm[host][proto][port]['state'] == 'open':
                        dns_hosts.append(host)

        if not dns_hosts:
            return {'hosts': {}, 'message': 'DNS-серверы не найдены'}

        results = {'hosts': {}}
        for host in dns_hosts:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [host]
                resolver.timeout = 2
                resolver.lifetime = 2
                answer = resolver.resolve('google.com', 'A')
                ips = [str(r) for r in answer]
                results['hosts'][host] = {
                    'responds': True,
                    'example_answer': ips,
                    'protocol': 'TCP/UDP' if privileged and is_root() else 'TCP'
                }
            except Exception as e:
                results['hosts'][host] = {
                    'responds': False,
                    'error': str(e),
                    'protocol': 'TCP/UDP' if privileged and is_root() else 'TCP'
                }
        
        return results
    except Exception as e:
        return {'error': f"Ошибка обработки результатов: {str(e)}"}

# CLI-интерфейс

def main():
    parser = argparse.ArgumentParser(description='Сканер сети для авиационной инфраструктуры')
    parser.add_argument('--target', required=True, help='Целевой IP-адрес или подсеть (например, 192.168.1.0/24)')
    parser.add_argument('--ports', default='1-1024', help='Диапазон портов (например, 1-65535)')
    parser.add_argument('--dns', help='Домен или IP для проверки DNS-записей')
    parser.add_argument('--vulns', action='store_true', help='Проверить базовые уязвимости (Telnet, SMB)')
    parser.add_argument('--privileged', action='store_true', help='Включить привилегированное сканирование (требует root)')
    parser.add_argument('--fast', action='store_true', help='Включить быстрый режим сканирования (менее точно, но быстрее)')
    parser.add_argument('--ping', action='store_true', help='Пинговать хост и показать задержку')
    parser.add_argument('--http-banner', action='store_true', help='Получить HTTP/HTTPS баннер')
    parser.add_argument('--ipv6', action='store_true', help='Проверить наличие IPv6-адреса')
    parser.add_argument('--scan-dns-servers', action='store_true', help='Сканировать подсеть на открытые DNS-серверы (53 порт) и протестировать их')
    
    args = parser.parse_args()
    
    if args.privileged and not is_root():
        print("Внимание: Запрошено привилегированное сканирование, но скрипт не запущен с правами root. Используется обычный режим.")
    
    if args.scan_dns_servers:
        dns_scan_result = scan_network_dns_servers(args.target, "53", args.privileged)
        
        if 'error' in dns_scan_result:
            print(f"\nОшибка: {dns_scan_result['error']}")
        
        if 'message' in dns_scan_result:
            print(f"\n{dns_scan_result['message']}")
        
        print("\nНайденные DNS-серверы в сети:")
        if 'hosts' in dns_scan_result:
            for host, info in dns_scan_result['hosts'].items():
                if info['responds']:
                    print(f"  {host} ({info['protocol']}): отвечает на DNS-запросы")
                    print(f"    Пример ответа: {', '.join(info['example_answer'])}")
                else:
                    print(f"  {host} ({info['protocol']}): не отвечает на DNS-запросы")
                    print(f"    Ошибка: {info['error']}")
    
    print(f"\nСканирование цели: {args.target} на портах {args.ports}")
    print(f"Режим: {'Быстрый' if args.fast else 'Обычный'}, {'привилегированный' if args.privileged and is_root() else 'обычный'}")
    
    port_results = scan_open_ports(args.target, args.ports, args.privileged, args.fast)
    
    if 'error' in port_results:
        print(f"Ошибка при сканировании портов: {port_results['error']}")
        print(port_results.get('recommendation', ''))
    else:
        print("\nРезультаты сканирования портов:")
        for host, host_data in port_results.items():
            print(f"\nХост: {host} ({host_data['state']})")
            for proto in ['tcp', 'udp']:
                if proto in host_data and host_data[proto]:
                    print(f"\nПорты {proto.upper()}:")
                    for port, port_data in host_data[proto].items():
                        print(f"  {port}/{proto}: {port_data['state']} - {port_data['service']} {port_data['product']} {port_data['version']}")
    
    if args.dns:
        print(f"\nПроверка DNS для {args.dns}")
        dns_result = check_dns(args.dns)
        print_dns_info(dns_result)
    
    if args.vulns:
        print(f"\nПроверка базовых уязвимостей для {args.target}")
        vuln_result = check_basic_vulns(args.target)
        print("[Результат проверки уязвимостей]")
        print(vuln_result)
    
    if args.ping:
        print(f"\nПинг {args.target}.")
        ping_result = ping_host(args.target)
        print(f"  Достижим: {ping_result['reachable']}, Средний пинг: {ping_result['avg_ping_ms']} мс")
    
    if args.http_banner:
        print(f"\nПолучение HTTP/HTTPS баннера для {args.target}.")
        banner = get_http_banner(args.target)
        for proto, info in banner.items():
            print(f"  {proto.upper()}:")
            print(f"    Статус: {info['status_code']}, Сервер: {info['server']}, Заголовок: {info['title']}")
    
    if args.ipv6:
        print(f"\nПроверка IPv6 для {args.target}.")
        ipv6_result = check_ipv6(args.target)
        print(f"  IPv6 доступен: {ipv6_result['ipv6']}")
        if ipv6_result['addresses']:
            for addr in ipv6_result['addresses']:
                print(f"    {addr}")

if __name__ == "__main__":
    main() 