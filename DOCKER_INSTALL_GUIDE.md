# 🐳 УСТАНОВКА DOCKER ДЛЯ ИЗОЛЯЦИИ ВРЕДОНОСОВ

## Быстрая установка (Ubuntu/Debian)

```bash
# 1. Обновление пакетов
apt-get update

# 2. Установка зависимостей
apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# 3. Добавление GPG ключа Docker
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# 4. Добавление репозитория
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# 5. Установка Docker
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io

# 6. Проверка
docker --version

# 7. Добавление пользователя в группу docker
usermod -aG docker $USER

# 8. Запуск Docker
systemctl start docker
systemctl enable docker
```

## После установки

```bash
# Выйдите и войдите снова для применения прав группы
# Или выполните:
newgrp docker

# Проверка
docker ps
```

## Запуск изоляции

```bash
cd /root/eyes_cerberus
./docker_containment_quickstart.sh
```

---

## ⚠️ АЛЬТЕРНАТИВА: ИЗОЛЯЦИЯ БЕЗ DOCKER

Если Docker установить невозможно, используйте **chroot-изоляцию**:

### Скрипт chroot-изоляции

```bash
#!/bin/bash
# /root/eyes_cerberus/chroot_containment.sh

# Создание изолированной среды
mkdir -p /var/malware_chroot/{bin,lib,lib64,malware,logs}

# Копирование малвари (не удаление!)
for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
    if [ -f "$f" ]; then
        cp "$f" /var/malware_chroot/malware/$(basename $f | tr '/' '_')
        chmod 000 "$f"  # Блокировка оригинала
    fi
done

# Монтирование proc/sys (для мониторинга)
mount -t proc proc /var/malware_chroot/proc 2>/dev/null || true

# Запуск в chroot (если доступен)
# chroot /var/malware_chroot /bin/bash

# Мониторинг
echo "Малварь изолирована в /var/malware_chroot/malware/"
echo "Оригиналы заблокированы (chmod 000)"
```

### Команды для chroot-изоляции

```bash
# 1. Создать изолированную директорию
mkdir -p /var/malware_isolation/{malware,logs}

# 2. Скопировать малварь (НЕ удалять!)
cp /let /var/malware_isolation/malware/let_root 2>/dev/null
cp /var/let /var/malware_isolation/malware/let_var 2>/dev/null
cp /dev/let /var/malware_isolation/malware/let_dev 2>/dev/null
cp /dev/shm/let /var/malware_isolation/malware/let_shm 2>/dev/null
cp /etc/let /var/malware_isolation/malware/let_etc 2>/dev/null
cp /tmp/let /var/malware_isolation/malware/let_tmp 2>/dev/null

# 3. Заблокировать оригиналы (chmod 000)
chmod 000 /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let 2>/dev/null

# 4. Установить мониторинг
inotifywait -m -r /var/malware_isolation/ >> /var/malware_isolation/logs/access.log 2>&1 &

# 5. Проверка
ls -la /var/malware_isolation/malware/
```

---

## 📊 СРАВНЕНИЕ МЕТОДОВ

| Метод | Безопасность | Изоляция | Сложность |
|-------|--------------|----------|-----------|
| Docker | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Средняя |
| chroot | ⭐⭐⭐ | ⭐⭐⭐ | Низкая |
| chmod 000 | ⭐⭐ | ⭐ | Очень низкая |

**Рекомендация:** Установить Docker для максимальной изоляции.

---

## 🔧 ПРОВЕРКА ПОСЛЕ УСТАНОВКИ

```bash
# Проверить Docker
docker --version && echo "✅ Docker OK"

# Запустить быстрый старт
cd /root/eyes_cerberus
./docker_containment_quickstart.sh

# Выбрать опцию 1 (Запустить изоляцию)
```

---

## 📞 ЕСЛИ ЧТО-ТО ПОШЛО НЕ ТАК

### Docker не запускается
```bash
# Проверить статус
systemctl status docker

# Перезапустить
systemctl restart docker

# Проверить логи
journalctl -u docker -n 50
```

### Нет прав доступа
```bash
# Добавить пользователя в группу
usermod -aG docker $USER

# Применить без выхода
newgrp docker

# Проверить
docker ps
```

### Контейнер не создаётся
```bash
# Проверить логи Docker
docker logs <container_name>

# Проверить образы
docker images | grep malware

# Пересоздать образ
cd /root/eyes_cerberus/containment
docker build -t malware-containment:latest .
```

---

**Готов к установке и развёртыванию!**
