# 🛡️ SYSTEM EYES - СТРАТЕГИЯ ИЗОЛЯЦИИ ВРЕДОНОСОВ
## Docker Containment Approach

**Дата:** 28 марта 2026  
**Статус:** ✅ ГОТОВО К РАЗВЁРТЫВАНИЮ

---

## 🎯 КОНЦЕПЦИЯ

Вместо **удаления** вредоносных файлов (что может вызвать срабатывание защиты), мы **изолируем** их в контролируемой среде Docker-контейнера.

```
┌─────────────────────────────────────────────────────────────────┐
│                    СТРАТЕГИЯ ИЗОЛЯЦИИ                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ДО:                                                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   /let      │    │  /var/let   │    │  /tmp/let   │        │
│  │   ⚠️ ACTIVE │    │   ⚠️ ACTIVE │    │   ⚠️ ACTIVE │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│         │                  │                  │                │
│         └──────────────────┼──────────────────┘                │
│                            ▼                                    │
│                    ┌───────────────┐                           │
│                    │   СИСТЕМА     │                           │
│                    │   ⚠️ UNDER    │                           │
│                    │   ATTACK      │                           │
│                    └───────────────┘                           │
│                                                                 │
│  ПОСЛЕ:                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   /let      │    │  /var/let   │    │  /tmp/let   │        │
│  │   🔒 LOCKED │    │   🔒 LOCKED │    │   🔒 LOCKED │        │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘        │
│         │                  │                  │                │
│         └──────────────────┼──────────────────┘                │
│                            ▼                                    │
│                   ┌─────────────────┐                          │
│                   │  Docker         │                          │
│                   │  Container      │                          │
│                   │  ┌───────────┐  │                          │
│                   │  │ /isolated │  │                          │
│                   │  │ let_root  │  │  НЕТ СЕТИ               │
│                   │  │ let_var   │  │  НЕТ ПРАВ               │
│                   │  │ let_tmp   │  │  МОНИТОРИНГ             │
│                   │  └───────────┘  │                          │
│                   └─────────────────┘                          │
│                            │                                    │
│                            ▼                                    │
│                    ┌───────────────┐                           │
│                    │   СИСТЕМА     │                           │
│                    │   ✅ SAFE     │                           │
│                    └───────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 ТЕХНИЧЕСКАЯ РЕАЛИЗАЦИЯ

### 1. Docker-контейнер с ограничениями

```yaml
Network:     none          # Полное отключение сети
Capabilities: DROP ALL     # Все capabilities отключены
Read-only:   true          # Файловая система только для чтения
tmpfs:       /tmp, /var/tmp # Временные файлы в памяти
PIDs Limit:  50            # Ограничение на процессы
Memory:      256MB         # Ограничение памяти
CPU:         5%            # Ограничение CPU
```

### 2. Bind Mounts для изоляции

| Хост (оригинал) | Контейнер (изоляция) | Описание |
|-----------------|----------------------|----------|
| `/var/malware_containment/let` | `/isolated/let` | Для /let |
| `/var/malware_containment/dev_shm` | `/isolated/dev_shm` | Для /dev/shm/let |
| `/var/malware_containment/dev` | `/isolated/dev` | Для /dev/let |
| `/var/malware_containment/etc` | `/isolated/etc` | Для /etc/let |
| `/var/malware_containment/tmp` | `/isolated/tmp` | Для /tmp/let |

### 3. Стратегия "Фейковых" файлов

```bash
# Оригинал остаётся на месте (для "защиты")
/let  → остаётся, но права 000

# Копия перемещается в контейнер
/let  → /isolated/let/let_root (в контейнере)

# Система "видит" файл, но не может выполнить
```

---

## 📋 ПОШАГОВЫЙ ПЛАН РАЗВЁРТЫВАНИЯ

### Шаг 1: Проверка Docker
```bash
# Проверить наличие Docker
docker --version

# Если не установлен - установить
curl -fsSL https://get.docker.com | sh

# Проверить статус
systemctl status docker
```

### Шаг 2: Запуск изоляции
```bash
# Перейти в директорию System Eyes
cd /root/eyes_cerberus

# Запустить изоляцию
./containment.sh setup
```

### Шаг 3: Проверка статуса
```bash
# Проверить статус контейнера
./containment.sh status

# Проверить Docker контейнеры
docker ps -a | grep malware

# Проверить изолированные файлы
docker exec malware_sandbox_* ls -la /malware/
```

### Шаг 4: Мониторинг
```bash
# Просмотр логов активности
docker exec malware_sandbox_* cat /malware/logs/activity.log

# Просмотр процессов в контейнере
docker exec malware_sandbox_* ps aux

# Проверка сетевых попыток
docker exec malware_sandbox_* netstat -tulpn
```

---

## 🔒 УРОВНИ ЗАЩИТЫ

### Уровень 1: Сетевая изоляция
```bash
--network none
```
- Полное отключение от сети
- Никаких подключений к C2
- Никакой эксфильтрации данных

### Уровень 2: Ограничение прав
```bash
--cap-drop=ALL
--cap-drop=NET_RAW
--cap-drop=SYS_ADMIN
--security-opt=no-new-privileges:true
```
- Отключены все Linux capabilities
- Никаких привилегированных операций
- Никакого escapes из контейнера

### Уровень 3: Файловая система
```bash
--read-only
--tmpfs /tmp:noexec,nosuid,size=100m
```
- Корневая ФС только для чтения
- Временные файлы в RAM
- noexec - нельзя запускать из /tmp

### Уровень 4: Ресурсы
```bash
--pids-limit 50
--memory 256m
--cpu-quota 50000
```
- Ограничение на процессы
- Ограничение памяти
- Ограничение CPU

### Уровень 5: Мониторинг
```bash
# Внутри контейнера
strace -p <pid>
lsof -p <pid>
tcpdump -i any
```
- Трассировка системных вызовов
- Мониторинг файловых дескрипторов
- Перехват сетевого трафика (даже если сети нет)

---

## 📊 МОНИТОРИНГ АКТИВНОСТИ

### Логи контейнера
```
/root/eyes_cerberus/containment/
├── logs/
│   ├── activity.log       # Общая активность
│   ├── processes.log      # Логи процессов
│   └── network.log        # Сетевые попытки
├── metadata.log           # Метаданные файлов
└── configs/               # Конфигурации
```

### Команды для проверки
```bash
# Проверить активность процессов
docker exec <container> ps auxf

# Проверить файловые операции
docker exec <container> ls -la /malware/

# Проверить сетевые попытки
docker exec <container> netstat -tulpn 2>&1 | grep -v "Cannot"

# Посмотреть логи
docker exec <container> cat /malware/logs/activity.log
```

---

## ⚠️ МЕРЫ ПРЕДОСТОРОЖНОСТИ

### 1. Регулярная проверка контейнера
```bash
# Ежедневная проверка
docker inspect <container> | grep -E "Status|Running"

# Проверка целостности
docker diff <container>
```

### 2. Бэкап изолированных файлов
```bash
# Экспорт контейнера с малварью
docker export <container> > malware_sandbox_backup_$(date +%Y%m%d).tar

# Сохранение в безопасное место
mv malware_sandbox_backup_*.tar /root/eyes_cerberus/evidence/
```

### 3. Алерты на подозрительную активность
```bash
# Скрипт проверки
cat > /etc/cron.hourly/malware_containment_check << 'EOF'
#!/bin/bash
if ! docker ps | grep -q malware_sandbox; then
    echo "WARNING: Malware containment container is NOT running!" | \
    mail -s "SECURITY ALERT" admin@example.com
fi
EOF
chmod +x /etc/cron.hourly/malware_containment_check
```

---

## 🔄 ПРОЦЕДУРА ВОССТАНОВЛЕНИЯ

### Если контейнер остановлен
```bash
# Перезапустить контейнер
docker start <container_name>

# Если не работает - пересоздать
cd /root/eyes_cerberus
./containment.sh remove
./containment.sh setup
```

### Если файлы были изменены
```bash
# Проверить изменения
docker diff <container>

# Вернуть оригинальные копии
# (оригиналы хранятся в /root/eyes_cerberus/containment/malware_source/)
```

### Если нужна срочная остановка
```bash
# Экстренная остановка
docker stop -t 0 <container_name>

# Блокировка на уровне хоста
iptables -A OUTPUT -p tcp --dport 9009 -j DROP
```

---

## 📈 ПРЕИМУЩЕСТВА ПОДХОДА

| Аспект | Удаление | Изоляция (Docker) |
|--------|----------|-------------------|
| Безопасность | ⚠️ Риск триггера | ✅ Безопасно |
| Анализ | ❌ Файлы утеряны | ✅ Можно изучать |
| Доказательства | ❌ Уничтожены | ✅ Сохранены |
| Восстановление | ❌ Невозможно | ✅ Полный откат |
| Мониторинг | ❌ Невозможен | ✅ Полный контроль |

---

## 🎯 СЛЕДУЮЩИЕ ШАГИ

1. **Развернуть изоляцию** - выполнить `./containment.sh setup`
2. **Проверить работу** - выполнить `./containment.sh status`
3. **Настроить мониторинг** - добавить cron jobs
4. **Документировать** - сохранить логи и метаданные

---

## 📞 ЭКСТРЕННЫЕ КОМАНДЫ

```bash
# Экстренная остановка контейнера
docker stop -t 0 $(docker ps -q -f name=malware_sandbox)

# Полное удаление
docker rm -f $(docker ps -aq -f name=malware_sandbox)

# Блокировка всей малвари на уровне хоста
chmod 000 /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let

# Проверка что контейнер работает
docker ps | grep malware_sandbox && echo "✅ CONTAINED" || echo "⚠️ NOT CONTAINED"
```

---

**Документ подготовлен:** System Eyes Defense Team  
**Версия:** 1.0  
**Статус:** ✅ ГОТОВО К РАЗВЁРТЫВАНИЮ

---

*«Сдержи, изучай, защищай» 👁️*
