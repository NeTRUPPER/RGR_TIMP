import nmap
import dns.resolver
import socket
import subprocess
import json
import shutil
import platform
import psutil
import ipaddress
import threading
import time
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import requests
import os

class NetworkScanner:
    def __init__(self):
        # Проверяем наличие nmap в системе
        if not shutil.which('nmap'):
            raise RuntimeError(
                "Nmap is not installed. Please install it using:\n"
                "sudo apt-get update && sudo apt-get install nmap"
            )
        self.nm = nmap.PortScanner()
    
    def scan_ports(self, ip: str) -> Dict[str, Any]:
        """Быстрое сканирование открытых портов через nmap (только 80, 443, 22, без -sV и -sC)"""
        try:
            popular_ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
            self.nm.scan(ip, popular_ports, '-sT -T4 --min-rate 1000 --max-retries 1')
            if ip in self.nm.all_hosts():
                host_data = self.nm[ip]
                ports_info = []
                # TCP
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            ports_info.append({
                                'port': port,
                                'service': port_data.get('name', ''),
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', ''),
                                'extrainfo': port_data.get('extrainfo', ''),
                                'script_output': port_data.get('script', {}),
                                'reason': port_data.get('reason', '')
                            })
                # UDP (не используется, но оставим для совместимости)
                udp_ports = []
                return {
                    'status': 'success',
                    'tcp_ports': ports_info,
                    'udp_ports': udp_ports,
                    'total_open_tcp': len(ports_info),
                    'total_open_udp': 0
                }
            return {'status': 'error', 'message': 'Host not found'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def analyze_subnet(self, network: str) -> Dict[str, Any]:
        """Анализ подсети"""
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            subnet_info = {
                'network_address': str(net.network_address),
                'broadcast_address': str(net.broadcast_address),
                'netmask': str(net.netmask),
                'total_hosts': net.num_addresses,
                'usable_hosts': net.num_addresses - 2,
                'subnet_bits': net.prefixlen,
                'host_bits': 32 - net.prefixlen
            }
            
            # Сканирование подсети для поиска активных хостов
            self.nm.scan(hosts=network, arguments='-sn')
            active_hosts = list(self.nm.all_hosts())
            
            subnet_info['active_hosts'] = len(active_hosts)
            subnet_info['host_utilization'] = f"{(len(active_hosts) / subnet_info['usable_hosts']) * 100:.1f}%"
            
            return subnet_info
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def check_dns(self, ip: str) -> Dict[str, Any]:
        """Расширенная проверка DNS-настроек"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            resolver = dns.resolver.Resolver()
            issues = []
            dns_info = {}
            
            # Проверка A-записи
            try:
                a_records = resolver.resolve(hostname, 'A')
                dns_info['a_records'] = [str(r) for r in a_records]
            except:
                issues.append('No A record found')
            
            # Проверка PTR-записи
            try:
                ptr_records = resolver.resolve(ip, 'PTR')
                dns_info['ptr_records'] = [str(r) for r in ptr_records]
            except:
                issues.append('No PTR record found')
            
            # Проверка MX-записей
            try:
                mx_records = resolver.resolve(hostname, 'MX')
                dns_info['mx_records'] = [str(r.exchange) for r in mx_records]
            except:
                pass
            
            # Проверка NS-записей
            try:
                ns_records = resolver.resolve(hostname, 'NS')
                dns_info['ns_records'] = [str(r) for r in ns_records]
            except:
                pass
            
            # Проверка TXT-записей
            try:
                txt_records = resolver.resolve(hostname, 'TXT')
                dns_info['txt_records'] = [str(r) for r in txt_records]
            except:
                pass
            
            # Проверка времени отклика DNS
            start_time = time.time()
            try:
                resolver.resolve(hostname, 'A')
                dns_info['response_time'] = f"{(time.time() - start_time) * 1000:.2f}ms"
            except:
                dns_info['response_time'] = 'timeout'
            
            return {
                'status': 'success',
                'hostname': hostname,
                'issues': issues,
                'dns_info': dns_info
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def check_security(self, ip: str) -> Dict[str, Any]:
        """Расширенная проверка безопасности"""
        issues = []
        security_info = {}
        risk_level = 'low'
        
        # Проверка небезопасных протоколов
        unsafe_ports = {
            23: 'Telnet (незащищенный)',
            21: 'FTP (незащищенный)',
            161: 'SNMP (незащищенный)',
            69: 'TFTP (незащищенный)',
            514: 'Syslog (незащищенный)',
            123: 'NTP (может быть уязвим)',
            67: 'DHCP (может быть уязвим)',
            389: 'LDAP (незащищенный)',
            139: 'NetBIOS (незащищенный)',
            445: 'SMB (может быть уязвим)',
            3389: 'RDP (может быть уязвим)',
            5900: 'VNC (может быть уязвим)',
            8080: 'HTTP Proxy (может быть уязвим)',
            3306: 'MySQL (может быть уязвим)',
            5432: 'PostgreSQL (может быть уязвим)',
            6379: 'Redis (может быть уязвим)',
            27017: 'MongoDB (может быть уязвим)'
        }
        
        for port, description in unsafe_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    issues.append(f'{description} (порт {port})')
                    if port in [23, 21, 161, 69]:
                        risk_level = 'high'
                    elif risk_level != 'high':
                        risk_level = 'medium'
                sock.close()
            except:
                pass
        
        # Проверка SSL/TLS
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    security_info['ssl_cert'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
        except:
            security_info['ssl_cert'] = 'SSL/TLS not available or error'
        
        # Проверка HTTP заголовков безопасности
        try:
            response = requests.get(f'http://{ip}', timeout=2, headers={'User-Agent': 'SecurityScanner/1.0'})
            security_headers = {}
            for header in ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 
                          'Strict-Transport-Security', 'Content-Security-Policy']:
                if header in response.headers:
                    security_headers[header] = response.headers[header]
                else:
                    security_headers[header] = 'Not set'
                    if header in ['X-Frame-Options', 'X-Content-Type-Options']:
                        issues.append(f'Missing security header: {header}')
            
            security_info['security_headers'] = security_headers
        except:
            security_info['security_headers'] = 'HTTP not available or error'
        
        return {
            'issues': issues,
            'security_info': security_info,
            'risk_level': risk_level,
            'total_issues': len(issues)
        }

    def check_network_config(self, ip: str) -> Dict[str, Any]:
        """Минимальная проверка: только порты 80, 443, 22 с минимальным таймаутом"""
        results = {}
        common_ports = [80, 443, 22]  # только самые важные порты
        port_availability = {}

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port, 'open' if result == 0 else 'closed'
            except:
                return port, 'error'

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(check_port, port) for port in common_ports]
            for future in as_completed(futures):
                port, status = future.result()
                port_availability[port] = status

        results['port_availability'] = port_availability
        return results

    def check_performance(self, ip: str) -> Dict[str, Any]:
        """Проверка производительности сети"""
        performance_data = {}
        
        # Тест пропускной способности (базовый)
        try:
            # Измеряем время загрузки веб-страницы
            start_time = time.time()
            response = requests.get(f'http://{ip}', timeout=2)
            load_time = (time.time() - start_time) * 1000
            
            performance_data['web_load_time'] = f"{load_time:.2f}ms"
            performance_data['web_status_code'] = response.status_code
            performance_data['web_content_length'] = len(response.content)
        except:
            performance_data['web_load_time'] = 'Failed'
            performance_data['web_status_code'] = 'N/A'
            performance_data['web_content_length'] = 'N/A'
        
        # Тест задержки сети
        try:
            ping_result = subprocess.run(['ping', '-c', '5', '-i', '0.2', ip],
                                       capture_output=True, text=True, timeout=2)
            lines = ping_result.stdout.split('\n')
            for line in lines:
                if 'rtt min/avg/max/mdev' in line:
                    parts = line.split('=')[1].strip().split('/')
                    performance_data['latency_min'] = f"{parts[0]}ms"
                    performance_data['latency_avg'] = f"{parts[1]}ms"
                    performance_data['latency_max'] = f"{parts[2]}ms"
                    performance_data['latency_jitter'] = f"{parts[3]}ms"
                    break
        except:
            performance_data['latency_stats'] = 'Failed'
        
        return performance_data

    def scan_network(self, network: str) -> List[Dict[str, Any]]:
        """Полное расширенное сканирование сети (ускорено: параллель по хостам и внутри хоста, с логированием времени)"""
        results = []
        subnet_info = self.analyze_subnet(network)
        self.nm.scan(hosts=network, arguments='-sn')
        active_hosts = list(self.nm.all_hosts())

        def scan_host(host):
            from concurrent.futures import ThreadPoolExecutor
            import time
            results_dict = {'ip_address': host, 'subnet_info': subnet_info, 'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')}
            def wrap(method, key):
                t0 = time.time()
                try:
                    res = method(host)
                    print(f'[{host}] {key} done in {time.time() - t0:.2f}s')
                    return key, res
                except Exception as e:
                    print(f'[{host}] {key} error: {e}')
                    return key, {'error': str(e)}
            tasks = [
                (self.scan_ports, 'open_ports'),
                (self.check_dns, 'dns_issues'),
                (self.check_security, 'security_issues'),
                (self.check_network_config, 'network_config'),
                (self.check_performance, 'performance_data'),
            ]
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_key = {executor.submit(wrap, func, key): key for func, key in tasks}
                for future in as_completed(future_to_key):
                    key, value = future.result()
                    results_dict[key] = value
            return results_dict

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(scan_host, host) for host in active_hosts]
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def scan_network_dns_servers(self, subnet: str, privileged: bool = False) -> dict:
        """Сканирует подсеть на открытые DNS-серверы (53 порт) и делает тестовый DNS-запрос."""
        nm = nmap.PortScanner()
        result = {
            'scan_info': f'Сканирование {subnet} на открытый 53 порт',
            'dns_servers': []
        }
        # Выбираем параметры сканирования в зависимости от прав
        if privileged and hasattr(os, 'geteuid') and os.geteuid() == 0:
            scan_args = '-sU -sT --open -T4 --min-rate 500'
        else:
            scan_args = '-sT --open -T4 --min-rate 500'
        try:
            nm.scan(subnet, '53', arguments=scan_args)
        except Exception as e:
            result['error'] = f'Ошибка сканирования: {e}'
            return result
        dns_hosts = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    if int(port) == 53 and nm[host][proto][port]['state'] == 'open':
                        dns_hosts.append(host)
        if not dns_hosts:
            result['message'] = 'DNS-серверы не найдены'
            return result
        for host in dns_hosts:
            entry = {'ip': host}
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [host]
                resolver.timeout = 2
                resolver.lifetime = 2
                answer = resolver.resolve('google.com', 'A')
                ips = [str(r) for r in answer]
                entry['responds'] = True
                entry['example_answer'] = ips
            except Exception as e:
                entry['responds'] = False
                entry['error'] = str(e)
            result['dns_servers'].append(entry)
        return result

    def get_http_banner(self, target: str) -> dict:
        """Пытается получить HTTP/HTTPS баннер с 80 и 443 порта."""
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

    def check_ipv6(self, target: str) -> dict:
        """Проверяет наличие IPv6-адреса у хоста."""
        try:
            result = socket.getaddrinfo(target, None, socket.AF_INET6)
            if result:
                return {'ipv6': True, 'addresses': [r[4][0] for r in result]}
            else:
                return {'ipv6': False, 'addresses': []}
        except Exception:
            return {'ipv6': False, 'addresses': []} 