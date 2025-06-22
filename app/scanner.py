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
        """Сканирование открытых портов с детальной информацией"""
        try:
            # Используем более подробное сканирование
            self.nm.scan(ip, '1-65535', '-sT -sV -sC --version-intensity 5')
            if ip in self.nm.all_hosts():
                host_data = self.nm[ip]
                ports_info = []
                
                # Получаем информацию о TCP портах
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            ports_info.append({
                                'port': port,
                                'service': port_data.get('name', 'unknown'),
                                'product': port_data.get('product', 'unknown'),
                                'version': port_data.get('version', 'unknown'),
                                'extrainfo': port_data.get('extrainfo', ''),
                                'script_output': port_data.get('script', {}),
                                'reason': port_data.get('reason', 'unknown')
                            })
                
                # Получаем информацию о UDP портах
                udp_ports = []
                if 'udp' in host_data:
                    for port, port_data in host_data['udp'].items():
                        if port_data['state'] == 'open':
                            udp_ports.append({
                                'port': port,
                                'service': port_data.get('name', 'unknown'),
                                'product': port_data.get('product', 'unknown'),
                                'version': port_data.get('version', 'unknown')
                            })
                
                return {
                    'status': 'success',
                    'tcp_ports': ports_info,
                    'udp_ports': udp_ports,
                    'total_open_tcp': len(ports_info),
                    'total_open_udp': len(udp_ports)
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

    def get_routing_info(self, ip: str) -> Dict[str, Any]:
        """Получение информации о маршрутизации"""
        routing_info = {}
        
        # Получение маршрута к хосту
        try:
            route_result = subprocess.run(['traceroute', '-n', '-w', '1', ip], 
                                        capture_output=True, text=True, timeout=30)
            routing_info['traceroute'] = route_result.stdout
            routing_info['hop_count'] = len([line for line in route_result.stdout.split('\n') 
                                           if '*' not in line and line.strip()])
        except:
            routing_info['traceroute'] = 'Error getting traceroute'
            routing_info['hop_count'] = 0
        
        # Получение локальной таблицы маршрутизации
        try:
            route_table = subprocess.run(['netstat', '-rn'], 
                                       capture_output=True, text=True)
            routing_info['local_routing_table'] = route_table.stdout
        except:
            routing_info['local_routing_table'] = 'Error getting routing table'
        
        return routing_info

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

    def check_services(self, ip: str) -> Dict[str, Any]:
        """Расширенная проверка доступности сервисов"""
        services = {
            'http': 80,
            'https': 443,
            'ftp': 21,
            'ssh': 22,
            'telnet': 23,
            'smtp': 25,
            'dns': 53,
            'pop3': 110,
            'imap': 143,
            'rdp': 3389,
            'mysql': 3306,
            'postgresql': 5432,
            'redis': 6379,
            'mongodb': 27017,
            'elasticsearch': 9200,
            'kibana': 5601,
            'jenkins': 8080,
            'tomcat': 8080,
            'apache': 80,
            'nginx': 80,
            'vnc': 5900,
            'sftp': 22,
            'ldap': 389,
            'ldaps': 636,
            'kerberos': 88,
            'ntp': 123,
            'snmp': 161,
            'dhcp': 67,
            'tftp': 69,
            'syslog': 514,
            'rsyslog': 514,
            'samba': 445,
            'netbios': 139,
            'iscsi': 3260,
            'iscsi_target': 3260,
            'iscsi_initiator': 3260,
            'iscsi_discovery': 3260,
            'iscsi_login': 3260,
            'iscsi_logout': 3260,
            'iscsi_text': 3260,
            'iscsi_data': 3260,
            'iscsi_ready': 3260,
            'iscsi_cleanup': 3260
        }
        
        results = {}
        open_services = []
        closed_services = []
        
        def check_service(service_name, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                start_time = time.time()
                result = sock.connect_ex((ip, port))
                response_time = (time.time() - start_time) * 1000
                
                if result == 0:
                    try:
                        service_name_resolved = socket.getservbyport(port)
                        service_info = {
                            'status': 'open',
                            'service_name': service_name_resolved,
                            'response_time': f"{response_time:.2f}ms"
                        }
                    except:
                        service_info = {
                            'status': 'open',
                            'service_name': 'unknown',
                            'response_time': f"{response_time:.2f}ms"
                        }
                    open_services.append(service_name)
                else:
                    service_info = {
                        'status': 'closed',
                        'service_name': 'unknown',
                        'response_time': f"{response_time:.2f}ms"
                    }
                    closed_services.append(service_name)
                
                sock.close()
                return service_name, service_info
            except Exception as e:
                return service_name, {
                    'status': 'error',
                    'service_name': 'unknown',
                    'error': str(e)
                }
        
        # Используем многопоточность для быстрой проверки сервисов
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_service = {
                executor.submit(check_service, service, port): service 
                for service, port in services.items()
            }
            
            for future in as_completed(future_to_service):
                service_name, service_info = future.result()
                results[service_name] = service_info
        
        return {
            'services': results,
            'open_services': open_services,
            'closed_services': closed_services,
            'total_checked': len(services),
            'total_open': len(open_services),
            'total_closed': len(closed_services)
        }

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
            import requests
            response = requests.get(f'http://{ip}', timeout=5, headers={'User-Agent': 'SecurityScanner/1.0'})
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
        """Расширенная проверка сетевой конфигурации"""
        results = {}
        
        # Проверка MTU
        try:
            ping_result = subprocess.run(['ping', '-c', '1', '-M', 'do', ip], 
                                       capture_output=True, text=True)
            if 'frag needed' in ping_result.stdout:
                results['mtu_issue'] = True
                results['mtu_message'] = 'MTU fragmentation required'
            else:
                results['mtu_issue'] = False
                results['mtu_message'] = 'MTU OK'
        except:
            results['mtu_issue'] = 'Unknown'
            results['mtu_message'] = 'MTU check failed'

        # Traceroute с детальной информацией
        try:
            traceroute = subprocess.run(['traceroute', '-n', '-w', '1', ip], 
                                      capture_output=True, text=True)
            results['traceroute'] = traceroute.stdout
            results['hop_count'] = len([line for line in traceroute.stdout.split('\n') 
                                      if '*' not in line and line.strip()])
        except:
            results['traceroute'] = 'Traceroute failed'
            results['hop_count'] = 0

        # Детальная проверка времени отклика
        try:
            ping_time = subprocess.run(['ping', '-c', '10', '-i', '0.2', ip],
                                     capture_output=True, text=True)
            results['ping_stats'] = ping_time.stdout
            
            # Парсинг статистики ping
            lines = ping_time.stdout.split('\n')
            for line in lines:
                if 'rtt min/avg/max/mdev' in line:
                    parts = line.split('=')[1].strip().split('/')
                    results['ping_min'] = f"{parts[0]}ms"
                    results['ping_avg'] = f"{parts[1]}ms"
                    results['ping_max'] = f"{parts[2]}ms"
                    results['ping_mdev'] = f"{parts[3]}ms"
                    break
        except:
            results['ping_stats'] = 'Ping test failed'

        # Проверка доступности портов для основных сервисов
        common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3389, 3306, 5432]
        port_availability = {}
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                port_availability[port] = 'open' if result == 0 else 'closed'
                sock.close()
            except:
                port_availability[port] = 'error'
        
        results['port_availability'] = port_availability
        
        return results

    def get_system_info(self, ip: str) -> Dict[str, Any]:
        """Расширенное получение информации о системе"""
        try:
            # Пробуем получить информацию о системе через nmap
            self.nm.scan(ip, arguments='-O --osscan-guess')
            if ip in self.nm.all_hosts():
                host_data = self.nm[ip]
                os_info = {}
                
                if 'osmatch' in host_data and host_data['osmatch']:
                    os_info['os_name'] = host_data['osmatch'][0].get('name', 'Unknown')
                    os_info['os_accuracy'] = host_data['osmatch'][0].get('accuracy', '0')
                    os_info['os_line'] = host_data['osmatch'][0].get('line', 'Unknown')
                else:
                    os_info['os_name'] = 'Unknown'
                    os_info['os_accuracy'] = '0'
                    os_info['os_line'] = 'Unknown'
                
                # Дополнительная информация о системе
                os_info['hostname'] = host_data.get('hostnames', [{}])[0].get('name', 'Unknown')
                os_info['mac_address'] = host_data.get('addresses', {}).get('mac', 'Unknown')
                os_info['vendor'] = host_data.get('vendor', {}).get(os_info['mac_address'], 'Unknown')
                
                return os_info
        except:
            pass
        return {
            'os_name': 'Unknown',
            'os_accuracy': '0',
            'os_line': 'Unknown',
            'hostname': 'Unknown',
            'mac_address': 'Unknown',
            'vendor': 'Unknown'
        }

    def check_performance(self, ip: str) -> Dict[str, Any]:
        """Проверка производительности сети"""
        performance_data = {}
        
        # Тест пропускной способности (базовый)
        try:
            # Измеряем время загрузки веб-страницы
            import requests
            start_time = time.time()
            response = requests.get(f'http://{ip}', timeout=10)
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
                                       capture_output=True, text=True)
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
        """Полное расширенное сканирование сети"""
        results = []
        
        # Анализ подсети
        subnet_info = self.analyze_subnet(network)
        
        # Сканирование сети для поиска активных хостов
        self.nm.scan(hosts=network, arguments='-sn')
        
        for host in self.nm.all_hosts():
            print(f"Scanning host: {host}")
            
            # Получаем всю информацию о хосте
            host_result = {
                'ip_address': host,
                'subnet_info': subnet_info,
                'system_info': self.get_system_info(host),
                'open_ports': self.scan_ports(host),
                'dns_issues': self.check_dns(host),
                'service_status': self.check_services(host),
                'security_issues': self.check_security(host),
                'network_config': self.check_network_config(host),
                'routing_info': self.get_routing_info(host),
                'performance_data': self.check_performance(host),
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            results.append(host_result)
        
        return results 