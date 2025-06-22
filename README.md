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
sudo ./stresser target.com ICMP 3000 120```

