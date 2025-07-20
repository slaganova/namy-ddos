# 🚀 Ultimate L3/L4/L7 Stress Testing Tool

## 📖 Описание
Многофункциональный инструмент для нагрузочного тестирования сетей и приложений на уровнях L3, L4 и L7. Поддерживает различные типы атак, работу через прокси, ротацию агентов и подробную статистику в реальном времени.

## 🏆 Возможности
- L3: SYN Flood, ICMP Flood
- L4: TCP Flood, UDP Flood, DNS Amplification
- L7: HTTP/HTTPS Flood, Slowloris
- Поддержка прокси (HTTP/S)
- Ротация User-Agent и методов
- Автоматическая ротация и проверка прокси
- Реальная статистика (RPS, успешные/неуспешные запросы)
- Гибкая настройка payload

## ⚡ Быстрый старт
```bash
git clone https://github.com/yourrepo/stress-tool.git
cd stress-tool
go build -o stresser
```

## 🔧 Требования
- Go 1.16+
- Linux/Windows/MacOS
- Доступ к интернету

## 🛠 Настройка прокси (опционально)
Создайте файл `proxies.txt`:
```bash
echo "1.1.1.1:8080" > proxies.txt
echo "2.2.2.2:3128" >> proxies.txt
```

## 🚀 Примеры запуска
### L3 (Network Layer)
```bash
./stresser target.com:80 SYN 5000 60
sudo ./stresser target.com ICMP 3000 120
```
### L4 (Transport Layer)
```bash
./stresser target.com:443 TCP 10000 300
./stresser target.com:53 UDP 8000 180
./stresser dns-server.com DNS 5000 60
```
### L7 (Application Layer)
```bash
./stresser http://target.com HTTP 20000 600
./stresser https://target.com HTTPS 15000 300
./stresser target.com:80 SLOWLORIS 500 3600
```

## ⚙️ Параметры
```
./stresser <цель> <тип атаки> <количество потоков> <время (сек)> [размер пакета]

Пример:
./stresser example.com:80 TCP 10000 60 1024
```
- `<цель>`: адрес или URL (например, example.com:80 или https://site.com)
- `<тип атаки>`: SYN, ICMP, TCP, UDP, DNS, HTTP, HTTPS, SLOWLORIS
- `<количество потоков>`: число параллельных воркеров (до 10000)
- `<время (сек)>`: продолжительность атаки
- `[размер пакета]`: размер payload (по умолчанию 1024)

## 📊 Пример вывода статистики
```
📊 Reqs: 50000 (2500.0/s) | Active: 1000 | Success: 98.5%
```

## 🧰 Дополнительные функции
- **Автоповтор**: переподключение при обрывах
- **Ротация прокси**: если указан proxies.txt
- **Ротация User-Agent и методов**
- **Статистика в реальном времени**

## ⚠️ Безопасность и ответственность
Инструмент предназначен только для тестирования собственных ресурсов или с разрешения владельца. Использование для атаки на чужие сервисы незаконно!

## 📄 Лицензия
MIT License
