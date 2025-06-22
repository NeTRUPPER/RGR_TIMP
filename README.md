# Airport Network Configuration Scanner

Инструмент для проверки сетевых конфигураций аэропортовой инфраструктуры.

## Функциональность

- Сканирование портов в указанных подсетях
- Проверка DNS-настроек
- Проверка доступности сервисов
- Проверка сетевой безопасности
- Проверка сетевой конфигурации

## Установка

1. Создайте виртуальное окружение:
```bash
python -m venv venv
source venv/bin/activate  # для Linux/Mac
# или
venv\Scripts\activate  # для Windows
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

3. Создайте файл .env и настройте переменные окружения:
```
DATABASE_URL=postgresql://user:password@localhost:5432/airport_scanner
```

4. Запустите приложение:
```bash
uvicorn app.main:app --reload
```

## Использование

Откройте браузер и перейдите по адресу http://localhost:8000