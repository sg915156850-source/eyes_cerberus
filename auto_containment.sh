#!/usr/bin/env bash
#===============================================================================
# SYSTEM EYES - AUTO-CONTAINMENT MODULE
# Автоматическая изоляция вредоносов при обнаружении
# 
# Что делает:
# 1. Мониторит процессы (CPU, сетевая активность, известные сигнатуры)
# 2. При обнаружении - КИЛЛИТ процесс
# 3. Копирует файл в изоляцию
# 4. Блокирует оригинал (chmod 000)
# 5. Блокирует сеть (iptables)
# 6. Логирует всё в evidence
#===============================================================================

set -euo pipefail

ROOT="/root/eyes_cerberus"
CONTAINMENT_DIR="/var/malware_containment"
LOG_FILE="$ROOT/auto_containment.log"
EVIDENCE_DIR="$ROOT/evidence/auto_$(date +%Y%m%d_%H%M%S)"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Пороги
CPU_THRESHOLD=60
NC_CONNECTION_THRESHOLD=3

# Известные C2
declare -a C2_IPS=("107.175.89.136" "87.121.84.56")
declare -a MALWARE_PATTERNS=("/let" "let$" "miner" "xmrig" "cryptonight" "nanopool")

log() {
    echo -e "${BLUE}[*]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

alert() {
    echo -e "${RED}[ALERT]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[+]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $(date -Iseconds) $*" | tee -a "$LOG_FILE"
}

#===============================================================================
# ИНИЦИАЛИЗАЦИЯ
#===============================================================================
init() {
    mkdir -p "$CONTAINMENT_DIR"/{malware,logs,metadata,evidence}
    mkdir -p "$EVIDENCE_DIR"
    touch "$LOG_FILE"
    
    log "=== Auto-Containment запущен ==="
    log "PID: $$"
    log "Evidence: $EVIDENCE_DIR"
}

#===============================================================================
# ФУНКЦИЯ 1: УБИТЬ ПРОЦЕСС
#===============================================================================
kill_process() {
    local pid=$1
    local comm=$2
    local reason=$3
    
    alert "Kill процесса: PID=$pid COMM=$comm REASON=$reason"
    
    # Собираем информацию перед убийством
    ps -p "$pid" -o pid,ppid,pcpu,pmem,user,etimes,cmd 2>/dev/null >> "$EVIDENCE_DIR/process_$pid.txt" || true
    pstree -p -a "$pid" 2>/dev/null >> "$EVIDENCE_DIR/process_$pid.txt" || true
    lsof -p "$pid" 2>/dev/null >> "$EVIDENCE_DIR/process_$pid.txt" || true
    
    # Kill
    kill -9 "$pid" 2>/dev/null && success "  Процесс убит" || warning "  Не удалось убить"
    
    # Kill детей
    pkill -9 -P "$pid" 2>/dev/null && success "  Дочерние процессы убиты" || true
}

#===============================================================================
# ФУНКЦИЯ 2: ИЗОЛИРОВАТЬ ФАЙЛ
#===============================================================================
isolate_file() {
    local filepath=$1
    local reason=$2
    
    if [ ! -f "$filepath" ]; then
        warning "Файл не найден: $filepath"
        return 1
    fi
    
    alert "Изоляция файла: $filepath REASON=$reason"
    
    local filename=$(basename "$filepath")
    local hash=$(md5sum "$filepath" | cut -d' ' -f1)
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Копируем в изоляцию
    local isolated_path="$CONTAINMENT_DIR/malware/${timestamp}_${filename}_${hash}"
    cp "$filepath" "$isolated_path" 2>/dev/null && success "  Копия: $isolated_path" || warning "  Не удалось скопировать"
    
    # Сохраняем метаданные
    {
        echo "=== MALWARE METADATA ==="
        echo "Original: $filepath"
        echo "Isolated: $isolated_path"
        echo "MD5: $hash"
        echo "Reason: $reason"
        echo "Time: $(date -Iseconds)"
        echo "Permissions: $(stat -c '%a' "$filepath" 2>/dev/null)"
        echo "Owner: $(stat -c '%U:%G' "$filepath" 2>/dev/null)"
        echo "Size: $(stat -c '%s' "$filepath" 2>/dev/null)"
        echo ""
    } >> "$EVIDENCE_DIR/metadata.log"
    
    # Блокируем оригинал (НЕ удаляем!)
    chmod 000 "$filepath" 2>/dev/null && success "  Оригинал заблокирован (chmod 000)" || warning "  Не удалось заблокировать"
    
    return 0
}

#===============================================================================
# ФУНКЦИЯ 3: БЛОКИРОВАТЬ СЕТЬ
#===============================================================================
block_network() {
    local ip=$1
    
    alert "Блокировка IP: $ip"
    
    # Проверяем есть ли уже правило
    if iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null; then
        warning "  Правило уже существует"
        return 0
    fi
    
    # Добавляем правило
    iptables -A OUTPUT -d "$ip" -j DROP 2>/dev/null && success "  IP заблокирован" || warning "  Не удалось (нет прав?)"
    
    # Логируем
    echo "$(date -Iseconds) BLOCKED: $ip" >> "$EVIDENCE_DIR/network_blocks.log"
}

#===============================================================================
# DETECTOR 1: NC К C2 СЕРВЕРАМ
#===============================================================================
detect_nc_connections() {
    local count=0
    
    for c2 in "${C2_IPS[@]}"; do
        local procs=$(ps aux | grep -E "nc\s+$c2" | grep -v grep | wc -l)
        count=$((count + procs))
        
        if [ "$procs" -gt 0 ]; then
            alert "Обнаружены NC подключения к $c2: $procs процессов"
            
            # Убиваем процессы
            ps aux | grep -E "nc\s+$c2" | grep -v grep | awk '{print $2}' | while read pid; do
                kill_process "$pid" "nc" "C2_CONNECTION:$c2"
            done
            
            # Блокируем IP
            block_network "$c2"
        fi
    done
    
    # Блокируем порт 9009
    local port9009=$(ps aux | grep -E "nc .* 9009" | grep -v grep | wc -l)
    if [ "$port9009" -gt 0 ]; then
        alert "Обнаружены NC подключения к порту 9009: $port9009 процессов"
        
        ps aux | grep -E "nc .* 9009" | grep -v grep | awk '{print $2}' | while read pid; do
            kill_process "$pid" "nc" "PORT_9009"
        done
        
        iptables -A OUTPUT -p tcp --dport 9009 -j DROP 2>/dev/null || true
    fi
}

#===============================================================================
# DETECTOR 2: МАЙНЕРЫ (xmr, nanopool, и т.д.)
#===============================================================================
detect_miners() {
    # Ищем процессы с именами майнеров
    local miner_patterns="xmrig|minerd|cpuminer|cryptonight|monero|nanopool|nicehash|minergate"
    
    ps aux | grep -iE "$miner_patterns" | grep -v grep | while read line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local comm=$(echo "$line" | awk '{print $11}')
        local cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        
        alert "Обнаружен майнер: PID=$pid CMD=$cmd"
        
        kill_process "$pid" "$comm" "MINER_DETECTED"
        
        # Пытаемся найти исполняемый файл
        local exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        if [ -n "$exe" ] && [ -f "$exe" ]; then
            isolate_file "$exe" "MINER_BINARY"
        fi
    done
    
    # Ищем подключения к майнинг-пулам
    local pool_patterns="nanopool\.org|nicehash\.com|minergate\.com|pool\.minexmr\.com"
    
    ss -tulpn 2>/dev/null | grep -iE "$pool_patterns" | while read line; do
        local pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || echo "")
        if [ -n "$pid" ]; then
            alert "Подключение к майнинг-пулу: PID=$pid"
            kill_process "$pid" "miner_network" "MINER_POOL_CONNECTION"
        fi
    done
}

#===============================================================================
# DETECTOR 3: ВЫСОКИЙ CPU (возможно майнер)
#===============================================================================
detect_high_cpu() {
    ps -eo pid,pcpu,comm,args --sort=-pcpu | head -20 | while read pid cpu comm args; do
        # Пропускаем системные процессы
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        grep -qF "$comm" "$ROOT/white_list.txt" 2>/dev/null && continue
        
        # Проверяем порог
        if (( $(echo "$cpu > $CPU_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
            warning "Высокий CPU: PID=$pid COMM=$comm CPU=$cpu%"
            
            # Собираем информацию
            local exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            if [ -n "$exe" ] && [ -f "$exe" ]; then
                # Проверяем на малварь
                local hash=$(md5sum "$exe" 2>/dev/null | cut -d' ' -f1)
                
                # Сравниваем с известными хэшами
                if grep -q "$hash" "$ROOT/known_malware_hashes.txt" 2>/dev/null; then
                    alert "Известная малварь по хэшу: $hash"
                    kill_process "$pid" "$comm" "KNOWN_MALWARE_HASH"
                    isolate_file "$exe" "KNOWN_MALWARE"
                fi
            fi
        fi
    done
}

#===============================================================================
# DETECTOR 4: ФАЙЛЫ МАЛВАРИ ПО ИЗВЕСТНЫМ ПУТЯМ
#===============================================================================
detect_malware_files() {
    local malware_paths="/let /var/let /dev/let /dev/shm/let /etc/let /tmp/let"
    
    for filepath in $malware_paths; do
        if [ -f "$filepath" ]; then
            local perms=$(stat -c '%a' "$filepath" 2>/dev/null)
            
            if [ "$perms" != "0" ]; then
                alert "Активный файл малвари: $filepath (perms: $perms)"
                isolate_file "$filepath" "KNOWN_MALWARE_PATH"
            fi
        fi
    done
}

#===============================================================================
# MAIN LOOP
#===============================================================================
main_loop() {
    log "Запуск основного цикла мониторинга..."
    log "Интервал: 10 секунд"
    log "CPU порог: $CPU_THRESHOLD%"
    
    while true; do
        # Детекторы
        detect_nc_connections
        detect_miners
        detect_high_cpu
        detect_malware_files
        
        # Пауза
        sleep 10
    done
}

#===============================================================================
# SIGNAL HANDLERS
#===============================================================================
cleanup() {
    log "Остановка auto-containment..."
    echo "$(date -Iseconds) STOPPED" >> "$LOG_FILE"
    exit 0
}

trap cleanup SIGINT SIGTERM

#===============================================================================
# ENTRY POINT
#===============================================================================
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}     SYSTEM EYES - AUTO-CONTAINMENT MODULE             ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}     Автоматическая изоляция вредоносов                ${BLUE}║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

init
main_loop
