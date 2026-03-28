#!/usr/bin/env bash
#===============================================================================
# SYSTEM EYES - MALWARE CONTAINMENT (Docker Isolation)
# Изоляция вредоносных файлов в Docker-контейнере
# 
# ПРИНЦИП РАБОТЫ:
# 1. Создаём изолированный контейнер без сетевого доступа
# 2. Перемещаем (не удаляем!) файлы малвари в контейнер
# 3. Создаём "фейковые" файлы на оригинальных местах (bind mount)
# 4. Мониторим активность внутри контейнера
#===============================================================================

set -euo pipefail

ROOT="/root/eyes_cerberus"
CONTAINMENT_DIR="$ROOT/containment"
CONTAINER_NAME="malware_sandbox_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$CONTAINMENT_DIR/containment.log"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[*]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[+]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

#===============================================================================
# ПРОВЕРКА ТРЕБОВАНИЙ
#===============================================================================
check_requirements() {
    log "Проверка требований..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker не найден! Установите Docker:"
        echo "  curl -fsSL https://get.docker.com | sh"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker не запущен или нет прав доступа"
        echo "  sudo systemctl start docker"
        echo "  sudo usermod -aG docker $USER"
        exit 1
    fi
    
    success "Docker доступен"
}

#===============================================================================
# СОЗДАНИЕ ИНФРАСТРУКТУРЫ
#===============================================================================
setup_infrastructure() {
    log "Создание инфраструктуры изоляции..."
    
    mkdir -p "$CONTAINMENT_DIR"/{malware_source,malware_fake,logs,configs}
    
    # Создаём директорию для "фейковых" файлов (оригинальные пути)
    # Эти файлы будут видны системе, но перенаправлены в контейнер
    mkdir -p /var/malware_containment
    mkdir -p /var/malware_containment/let
    mkdir -p /var/malware_containment/dev_shm
    mkdir -p /var/malware_containment/dev
    mkdir -p /var/malware_containment/etc
    mkdir -p /var/malware_containment/tmp
    
    success "Инфраструктура создана"
}

#===============================================================================
# DOCKERFILE ДЛЯ ИЗОЛЯЦИИ
#===============================================================================
create_dockerfile() {
    log "Создание Dockerfile для изоляции..."
    
    cat > "$CONTAINMENT_DIR/Dockerfile" << 'DOCKERFILE'
FROM alpine:latest

# Устанавливаем инструменты мониторинга
RUN apk add --no-cache \
    strace \
    lsof \
    net-tools \
    procps \
    bash \
    tcpdump \
    && rm -rf /var/cache/apk/*

# Создаём директорию для малвари
RUN mkdir -p /malware \
    && mkdir -p /malware/logs \
    && mkdir -p /malware/execution

# Отключаем сетевой доступ на уровне контейнера
# (будет дополнительно отключено при запуске)

# Скрипт мониторинга активности
RUN echo '#!/bin/bash
echo "=== Malware Containment Monitor ===" > /malware/logs/activity.log
echo "Started: $(date)" >> /malware/logs/activity.log

# Мониторим все процессы
while true; do
    ps aux >> /malware/logs/processes.log 2>&1
    netstat -tulpn >> /malware/logs/network.log 2>&1
    sleep 5
done
' > /monitor.sh && chmod +x /monitor.sh

# Точка входа
ENTRYPOINT ["/bin/bash", "-c", "while true; do sleep 3600; done"]
DOCKERFILE
    
    success "Dockerfile создан"
}

#===============================================================================
# СБОРКА ОБРАЗА
#===============================================================================
build_image() {
    log "Сборка Docker образа..."
    
    local IMAGE_NAME="malware-containment:latest"
    
    cd "$CONTAINMENT_DIR"
    docker build -t "$IMAGE_NAME" . > "$CONTAINMENT_DIR/build.log" 2>&1
    
    if [ $? -eq 0 ]; then
        success "Образ собран: $IMAGE_NAME"
    else
        error "Ошибка сборки образа!"
        cat "$CONTAINMENT_DIR/build.log"
        exit 1
    fi
    
    cd - > /dev/null
}

#===============================================================================
# ЗАПУСК КОНТЕЙНЕРА
#===============================================================================
start_container() {
    log "Запуск контейнера изоляции..."
    
    # Запускаем контейнер БЕЗ сети, с ограниченными правами
    docker run -d \
        --name "$CONTAINER_NAME" \
        --network none \
        --cap-drop=ALL \
        --cap-drop=NET_RAW \
        --cap-drop=SYS_ADMIN \
        --cap-drop=SYS_PTRACE \
        --security-opt=no-new-privileges:true \
        --read-only \
        --tmpfs /tmp:noexec,nosuid,size=100m \
        --tmpfs /var/tmp:noexec,nosuid,size=50m \
        -v "$CONTAINMENT_DIR/malware_source:/malware:rw" \
        -v "$CONTAINMENT_DIR/logs:/malware/logs:rw" \
        -v /var/malware_containment/let:/isolated/let:rw \
        -v /var/malware_containment/dev_shm:/isolated/dev_shm:rw \
        -v /var/malware_containment/dev:/isolated/dev:rw \
        -v /var/malware_containment/etc:/isolated/etc:rw \
        -v /var/malware_containment/tmp:/isolated/tmp:rw \
        --pids-limit 50 \
        --memory 256m \
        --cpu-quota 50000 \
        malware-containment:latest
    
    if [ $? -eq 0 ]; then
        success "Контейнер запущен: $CONTAINER_NAME"
        echo "  ID: $(docker ps -q -f name=$CONTAINER_NAME)"
        echo "  Статус: $(docker inspect -f '{{.State.Status}}' $CONTAINER_NAME)"
    else
        error "Ошибка запуска контейнера!"
        exit 1
    fi
}

#===============================================================================
# ПЕРЕМЕЩЕНИЕ МАЛВАРИ В ИЗОЛЯЦИЮ
#===============================================================================
# ВНИМАНИЕ: Мы НЕ удаляем файлы, а создаём их копии в контейнере
# Оригинальные файлы остаются на месте для "защиты"
move_malware_to_containment() {
    log "Перемещение образцов малвари в контейнер..."
    
    local MALWARE_PATHS=(
        "/let:/isolated/let/let_root"
        "/var/let:/isolated/let/let_var"
        "/dev/let:/isolated/dev/let_dev"
        "/dev/shm/let:/isolated/dev_shm/let_shm"
        "/etc/let:/isolated/etc/let_etc"
        "/tmp/let:/isolated/tmp/let_tmp"
    )
    
    local CONTAINER_ID=$(docker ps -q -f name=$CONTAINER_NAME)
    
    for mapping in "${MALWARE_PATHS[@]}"; do
        local src="${mapping%%:*}"
        local dst="${mapping##*:}"
        
        if [ -f "$src" ]; then
            # Копируем файл в контейнер (не удаляем оригинал!)
            docker cp "$src" "$CONTAINER_ID:$dst"
            
            # Сохраняем метаданные
            local hash=$(md5sum "$src" | cut -d' ' -f1)
            local perms=$(stat -c '%a' "$src")
            local size=$(stat -c '%s' "$src")
            
            echo "Файл: $src" >> "$CONTAINMENT_DIR/metadata.log"
            echo "  Копия в: $dst" >> "$CONTAINMENT_DIR/metadata.log"
            echo "  MD5: $hash" >> "$CONTAINMENT_DIR/metadata.log"
            echo "  Permissions: $perms" >> "$CONTAINMENT_DIR/metadata.log"
            echo "  Size: $size" >> "$CONTAINMENT_DIR/metadata.log"
            echo "  Время: $(date -Iseconds)" >> "$CONTAINMENT_DIR/metadata.log"
            echo "" >> "$CONTAINMENT_DIR/metadata.log"
            
            success "Скопировано: $src → $dst (MD5: $hash)"
        else
            warning "Файл не найден: $src"
        fi
    done
    
    # Копируем малварь из standalone директории
    if [ -f "/root/NaviomSite/server-deploy/site/.next/standalone/let" ]; then
        docker cp "/root/NaviomSite/server-deploy/site/.next/standalone/let" \
                  "$CONTAINER_ID:/malware/let_standalone"
        success "Скопировано: standalone/let"
    fi
}

#===============================================================================
# СОЗДАНИЕ "ФЕЙКОВЫХ" ФАЙЛОВ (для обхода защиты)
#===============================================================================
create_decoy_files() {
    log "Создание файлов-пустышек на оригинальных местах..."
    
    # Создаём файлы того же размера но с нулевым содержимым
    # Это обманет проверку "существования" файлов
    
    local MALWARE_PATHS=(
        "/let"
        "/var/let"
        "/dev/let"
        "/dev/shm/let"
        "/etc/let"
        "/tmp/let"
    )
    
    for path in "${MALWARE_PATHS[@]}"; do
        if [ -f "$path" ]; then
            local size=$(stat -c '%s' "$path")
            
            # Сохраняем оригинал в контейнере (уже сделано выше)
            # Создаём пустышку на оригинальном месте
            # dd if=/dev/zero of="$path.tmp" bs=1 count=$size 2>/dev/null
            # mv "$path" "$path.original"
            # mv "$path.tmp" "$path"
            
            # Альтернативно: просто меняем права на 000
            chmod 000 "$path" 2>/dev/null || warning "Не удалось изменить права: $path"
            
            warning "Файл заблокирован: $path (права 000)"
        fi
    done
}

#===============================================================================
# МОНТОРИНГ АКТИВНОСТИ
#===============================================================================
start_monitoring() {
    log "Запуск мониторинга активности в контейнере..."
    
    # Запускаем мониторинг процессов внутри контейнера
    docker exec "$CONTAINER_NAME" sh -c '
        while true; do
            ps aux >> /malware/logs/processes_$(date +%Y%m%d).log 2>&1
            sleep 10
        done
    ' &
    
    # Логируем сетевые попытки (даже если сети нет)
    docker exec "$CONTAINER_NAME" sh -c '
        while true; do
            netstat -tulpn >> /malware/logs/network_$(date +%Y%m%d).log 2>&1
            sleep 10
        done
    ' &
    
    success "Мониторинг запущен"
}

#===============================================================================
# ОТЧЁТ О СОСТОЯНИИ
#===============================================================================
status_report() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}║${NC}  SYSTEM EYES - СТАТУС ИЗОЛЯЦИИ МАЛВАРИ"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Статус контейнера
    if docker ps -a --format '{{.Names}}' | grep -q "$CONTAINER_NAME"; then
        local status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null)
        local started=$(docker inspect -f '{{.State.StartedAt}}' "$CONTAINER_NAME" 2>/dev/null)
        
        if [ "$status" = "running" ]; then
            success "Контейнер изоляции: РАБОТАЕТ"
        else
            warning "Контейнер изоляции: $status"
        fi
        
        echo "  Имя: $CONTAINER_NAME"
        echo "  Статус: $status"
        echo "  Запущен: $started"
    else
        error "Контейнер изоляции: НЕ НАЙДЕН"
    fi
    
    echo ""
    echo "=== Файлы малвари ==="
    
    # Проверяем оригинальные файлы
    for path in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
        if [ -f "$path" ]; then
            local perms=$(stat -c '%a' "$path" 2>/dev/null)
            local size=$(stat -c '%s' "$path" 2>/dev/null)
            if [ "$perms" = "0" ]; then
                warning "$path - ЗАБЛОКИРОВАН (perms: $perms, size: $size)"
            else
                error "$path - АКТИВЕН (perms: $perms, size: $size) ⚠️"
            fi
        else
            echo "$path - не найден"
        fi
    done
    
    echo ""
    echo "=== Копии в контейнере ==="
    docker exec "$CONTAINER_NAME" ls -la /malware/ 2>/dev/null || echo "  Нет данных"
    
    echo ""
    echo "=== Сетевая изоляция ==="
    docker exec "$CONTAINER_NAME" netstat -tulpn 2>/dev/null | head -5 || echo "  Сеть отключена ✓"
    
    echo ""
    echo "=== Последние логи ==="
    tail -10 "$CONTAINMENT_DIR/metadata.log" 2>/dev/null || echo "  Нет логов"
    
    echo ""
}

#===============================================================================
# УПРАВЛЕНИЕ
#===============================================================================
stop_container() {
    log "Остановка контейнера..."
    docker stop "$CONTAINER_NAME" 2>/dev/null && success "Контейнер остановлен"
}

remove_container() {
    log "Удаление контейнера..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null && success "Контейнер удалён"
}

show_logs() {
    echo "=== Логи активности ==="
    cat "$CONTAINMENT_DIR/metadata.log" 2>/dev/null
    
    echo ""
    echo "=== Логи процессов ==="
    ls -la "$CONTAINMENT_DIR/logs/" 2>/dev/null
}

#===============================================================================
# MAIN
#===============================================================================
usage() {
    echo ""
    echo "SYSTEM EYES - Malware Containment (Docker Isolation)"
    echo ""
    echo "Использование: $0 <команда>"
    echo ""
    echo "Команды:"
    echo "  setup     - Создать инфраструктуру и запустить изоляцию"
    echo "  status    - Показать статус изоляции"
    echo "  logs      - Показать логи"
    echo "  stop      - Остановить контейнер"
    echo "  remove    - Удалить контейнер"
    echo "  help      - Эта справка"
    echo ""
    echo "Полный цикл:"
    echo "  $0 setup    # Создать и запустить изоляцию"
    echo "  $0 status   # Проверить статус"
    echo ""
}

case "${1:-help}" in
    setup)
        check_requirements
        setup_infrastructure
        create_dockerfile
        build_image
        start_container
        move_malware_to_containment
        create_decoy_files
        start_monitoring
        status_report
        ;;
    status)
        status_report
        ;;
    logs)
        show_logs
        ;;
    stop)
        stop_container
        ;;
    remove)
        stop_container
        remove_container
        ;;
    help|*)
        usage
        ;;
esac
