# Сетевой сканер для аудита безопасности

Инструмент для комплексного сканирования и аудита сетевой инфраструктуры. Позволяет проверять открытые порты, DNS-конфигурацию, наличие уязвимых сервисов и многое другое.

## Возможности

- 🔍 Сканирование TCP и UDP портов (1-65535)
- 🌐 Расширенная проверка DNS (A, PTR, MX, NS, TXT, SPF, DKIM, DMARC)
- ⚠️ Поиск уязвимых сервисов (Redis, MongoDB, Elasticsearch и др.)
- 🛡️ Базовые проверки безопасности (Telnet, SMB)
- 📊 Подробная информация о каждом найденном сервисе

## Установка

1. Убедитесь, что у вас установлен Python 3.7+ и pip

2. Установите nmap:
```bash
sudo apt-get update
sudo apt-get install nmap
```

3. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd RGR_TIMP
```

4. Создайте виртуальное окружение и активируйте его:
```bash
python -m venv venv
source venv/bin/activate  # для Linux/Mac
# или
venv\Scripts\activate  # для Windows
```

5. Установите зависимости:
```bash
pip install -r requirements.txt
```

## Использование

### Базовое сканирование портов:
```bash
python -m app.network_scanner_scripts --target 192.168.1.1
```

### Сканирование с указанием диапазона портов:
```bash
python -m app.network_scanner_scripts --target 192.168.1.1 --ports 1-1000
```

### Проверка DNS для домена или IP:
```bash
python -m app.network_scanner_scripts --target 192.168.1.1 --dns example.com
```

### Поиск базовых уязвимостей:
```bash
python -m app.network_scanner_scripts --target 192.168.1.1 --vulns
```

### Поиск открытых опасных сервисов:
```bash
python -m app.network_scanner_scripts --target 192.168.1.1 --exposed
```

### Полное сканирование со всеми проверками:
```bash
python -m app.network_scanner_scripts --target 192.168.1.1 --ports 1-65535 --dns example.com --vulns --exposed
```

## Параметры командной строки

- `--target` - IP-адрес или подсеть для сканирования (например, 192.168.1.0/24)
- `--ports` - Диапазон портов для сканирования (по умолчанию: 1-65535)
- `--dns` - Домен или IP для проверки DNS-конфигурации
- `--vulns` - Включить проверку базовых уязвимостей (Telnet, SMB)
- `--exposed` - Искать открытые опасные сервисы

## Что проверяется

### Порты и сервисы
- TCP и UDP порты
- Версии сервисов
- Продукты и их версии
- Дополнительная информация о сервисах

### DNS-проверки
- A-записи (соответствие домена и IP)
- PTR-записи (обратное разрешение)
- MX-записи (почтовые серверы)
- NS-записи (серверы имён)
- TXT-записи
- SPF, DKIM, DMARC записи
- Время отклика DNS
- Совпадение прямого и обратного разрешения

### Опасные сервисы
- Redis без пароля
- MongoDB без аутентификации
- Elasticsearch без защиты
- RabbitMQ с открытой панелью управления
- Jenkins с открытой панелью управления
- Docker API без аутентификации
- VNC без пароля
- RDP
- SNMP с public community
- SIP
- MQTT без аутентификации
- Memcached без защиты

## Примеры вывода

### Сканирование портов:
```json
{
    "192.168.1.1": {
        "state": "up",
        "tcp": {
            "80": {
                "state": "open",
                "service": "http",
                "product": "nginx",
                "version": "1.18.0"
            }
        }
    }
}
```

### DNS-проверка:
```json
{
    "A": ["93.184.216.34"],
    "PTR": ["example.com"],
    "MX": ["mail.example.com"],
    "NS": ["ns1.example.com", "ns2.example.com"],
    "response_time": "45.23ms"
}
```

### Опасные сервисы:
```json
{
    "redis": "Открыт, не требует пароля!",
    "mongodb": "Открыт, не требует аутентификации!",
    "elasticsearch": "Открыт, не требует аутентификации!"
}
```