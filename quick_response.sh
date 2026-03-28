#!/usr/bin/env bash
#===============================================================================
# SYSTEM EYES - QUICK RESPONSE CARD
# Быстрые команды для реагирования на инцидент
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}║${NC}  SYSTEM EYES - $1"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

case "${1:-help}" in
    status)
        print_header "ПРОВЕРКА СТАТУСА УГРОЗЫ"
        echo ""
        
        # Проверка малварных процессов
        NC_COUNT=$(ps aux | grep -E "nc\s+(107\.175\.89\.136|87\.121\.84\.56)" | grep -v grep | wc -l)
        if [ "$NC_COUNT" -gt 0 ]; then
            print_error "Обнаружено NC процессов к C2: $NC_COUNT"
        else
            print_status "NC процессов к C2: 0"
        fi
        
        # Проверка файлов малвари
        MALWARE_FILES=0
        for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
            if [ -f "$f" ]; then
                MALWARE_FILES=$((MALWARE_FILES + 1))
            fi
        done
        
        if [ "$MALWARE_FILES" -gt 0 ]; then
            print_error "Файлов малвари найдено: $MALWARE_FILES"
        else
            print_status "Файлов малвари: 0"
        fi
        
        # Проверка next-server
        NEXT_SERVER=$(ps aux | grep "next-server.*v15" | grep -v grep | wc -l)
        if [ "$NEXT_SERVER" -gt 0 ]; then
            print_warning "Next-server v15 работает: $NEXT_SERVER процессов"
        else
            print_status "Next-server v15: не работает"
        fi
        
        # Проверка защиты
        if pgrep -f "anti_malware.sh" > /dev/null; then
            print_status "Anti-malware мониторинг: АКТИВЕН"
        else
            print_warning "Anti-malware мониторинг: НЕ АКТИВЕН"
        fi
        
        echo ""
        ;;
        
    stop)
        print_header "ЭКСТРЕННАЯ ОСТАНОВКА УГРОЗЫ"
        echo ""
        
        print_warning "Останавливаю вредоносные процессы..."
        
        # Найти и убить next-server v15
        PID=$(ps aux | grep "next-server.*v15" | grep -v grep | awk '{print $2}' | head -1)
        if [ -n "$PID" ]; then
            kill -9 $PID 2>/dev/null && print_status "Убит next-server v15 (PID: $PID)" || print_error "Не удалось убить PID $PID"
        fi
        
        # Убить nc процессы
        pkill -9 -f "nc 107.175.89.136" 2>/dev/null && print_status "Убиты nc к 107.175.89.136"
        pkill -9 -f "nc 87.121.84.56" 2>/dev/null && print_status "Убиты nc к 87.121.84.56"
        
        # Убить процессы /let
        pkill -9 -f "/let" 2>/dev/null && print_status "Убиты процессы /let"
        
        print_warning "Проверьте статус командой: $0 status"
        echo ""
        ;;
        
    block)
        print_header "БЛОКИРОВКА C2 СЕРВЕРОВ"
        echo ""
        
        print_status "Блокирую 107.175.89.136..."
        iptables -A OUTPUT -d 107.175.89.136 -j DROP 2>/dev/null && print_status "Заблокировано" || print_warning "Не удалось (нет iptables?)"
        
        print_status "Блокирую 87.121.84.56..."
        iptables -A OUTPUT -d 87.121.84.56 -j DROP 2>/dev/null && print_status "Заблокировано" || print_warning "Не удалось (нет iptables?)"
        
        print_status "Блокирую порт 9009..."
        iptables -A OUTPUT -p tcp --dport 9009 -j DROP 2>/dev/null && print_status "Заблокировано" || print_warning "Не удалось (нет iptables?)"
        
        echo ""
        print_warning "Для проверки: iptables -L -n"
        echo ""
        ;;
        
    quarantine)
        print_header "КАРАНТИН МАЛВАРИ"
        echo ""
        
        QUARANTINE_DIR="/root/eyes_cerberus/quarantine/malware_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$QUARANTINE_DIR"
        
        COUNT=0
        for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
            if [ -f "$f" ]; then
                HASH=$(md5sum "$f" | cut -d' ' -f1)
                mv "$f" "$QUARANTINE_DIR/$(basename $f)_$HASH" 2>/dev/null && {
                    print_status "Перемещено: $f"
                    COUNT=$((COUNT + 1))
                }
            fi
        done
        
        echo ""
        if [ "$COUNT" -gt 0 ]; then
            print_status "В карантин перемещено файлов: $COUNT"
            print_status "Директория: $QUARANTINE_DIR"
        else
            print_warning "Файлов малвари не найдено"
        fi
        echo ""
        ;;
        
    evidence)
        print_header "СБОР ДОКАЗАТЕЛЬСТВ"
        echo ""
        
        EVIDENCE_DIR="/root/eyes_cerberus/evidence/$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$EVIDENCE_DIR"
        
        print_status "Создана директория: $EVIDENCE_DIR"
        
        # Процесс tree
        ps auxf > "$EVIDENCE_DIR/process_tree.txt" 2>/dev/null && print_status "Сохранён process tree"
        
        # Сетевые подключения
        ss -tulpn > "$EVIDENCE_DIR/network_connections.txt" 2>/dev/null && print_status "Сохранены сетевые подключения"
        
        # Хэши малвари
        for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
            if [ -f "$f" ]; then
                md5sum "$f" >> "$EVIDENCE_DIR/malware_hashes.txt" 2>/dev/null
            fi
        done
        [ -f "$EVIDENCE_DIR/malware_hashes.txt" ] && print_status "Сохранены хэши малвари"
        
        # Лог запущенных процессов
        ps aux | grep -E "nc|/let|next-server" | grep -v grep > "$EVIDENCE_DIR/suspicious_processes.txt" 2>/dev/null && print_status "Сохранены подозрительные процессы"
        
        echo ""
        print_status "Доказательства собраны в: $EVIDENCE_DIR"
        echo ""
        ;;
        
    scan)
        print_header "СКАНИРОВАНИЕ НА МАЛВАРЬ"
        echo ""
        
        print_status "Поиск файлов с известным хэшем..."
        FOUND=0
        for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
            if [ -f "$f" ]; then
                HASH=$(md5sum "$f" | cut -d' ' -f1)
                if [ "$HASH" = "ac65b89c09bbb53406dad3d42915c231" ]; then
                    print_error "НАЙДЕНА МАЛВАРЬ: $f"
                    FOUND=$((FOUND + 1))
                fi
            fi
        done
        
        if [ "$FOUND" -eq 0 ]; then
            print_status "Известных файлов малвари не найдено"
        fi
        
        echo ""
        print_status "Поиск UPX-упакованных файлов в /tmp /var/tmp /dev/shm..."
        for f in $(find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null); do
            if strings "$f" 2>/dev/null | grep -q "UPX!"; then
                print_warning "UPX файл: $f"
            fi
        done
        
        echo ""
        ;;
        
    monitor)
        print_header "ЗАПУСК МОНИТОРИНГА"
        echo ""
        
        if pgrep -f "anti_malware.sh" > /dev/null; then
            print_warning "Мониторинг уже запущен"
        else
            nohup /root/eyes_cerberus/defense/anti_malware.sh monitor > /root/eyes_cerberus/defense/monitor.log 2>&1 &
            print_status "Мониторинг запущен (PID: $!)"
        fi
        
        echo ""
        print_warning "Для остановки: pkill -f anti_malware.sh"
        echo ""
        ;;
        
    report)
        print_header "ГЕНЕРАЦИЯ ОТЧЁТА"
        echo ""
        
        REPORT_FILE="/root/eyes_cerberus/reports/status_$(date +%Y%m%d_%H%M%S).txt"
        mkdir -p /root/eyes_cerberus/reports
        
        {
            echo "SYSTEM EYES STATUS REPORT"
            echo "Generated: $(date)"
            echo ""
            echo "=== Malware Files ==="
            for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
                if [ -f "$f" ]; then
                    echo "FOUND: $f ($(md5sum $f | cut -d' ' -f1))"
                fi
            done
            echo ""
            echo "=== Malicious Processes ==="
            ps aux | grep -E "nc\s+(107\.175\.89\.136|87\.121\.84\.56)" | grep -v grep || echo "None found"
            echo ""
            echo "=== Next.js Servers ==="
            ps aux | grep "next-server" | grep -v grep || echo "None running"
            echo ""
            echo "=== Network Connections (suspicious ports) ==="
            ss -tulpn | grep -E "9009|14444|4444" || echo "None on suspicious ports"
            echo ""
            echo "=== Recent Alerts ==="
            tail -20 /root/eyes_cerberus/hunt.log 2>/dev/null || echo "No hunt log"
            tail -20 /root/eyes_cerberus/defense/defense.log 2>/dev/null || echo "No defense log"
        } > "$REPORT_FILE"
        
        print_status "Отчёт сохранён: $REPORT_FILE"
        echo ""
        cat "$REPORT_FILE"
        echo ""
        ;;
        
    help|*)
        echo ""
        echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}     SYSTEM EYES - QUICK RESPONSE CARD                 ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}     Экстренное реагирование на инцидент               ${BLUE}║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "Использование: $0 <команда>"
        echo ""
        echo "Команды:"
        echo "  ${GREEN}status${NC}     - Проверка текущего статуса угрозы"
        echo "  ${GREEN}stop${NC}       - Экстренная остановка вредоносных процессов"
        echo "  ${GREEN}block${NC}      - Блокировка C2 серверов (iptables)"
        echo "  ${GREEN}quarantine${NC} - Перемещение малвари в карантин"
        echo "  ${GREEN}evidence${NC}   - Сбор доказательств"
        echo "  ${GREEN}scan${NC}       - Сканирование на наличие малвари"
        echo "  ${GREEN}monitor${NC}    - Запуск постоянного мониторинга"
        echo "  ${GREEN}report${NC}     - Генерация отчёта о состоянии"
        echo "  ${GREEN}help${NC}       - Эта справка"
        echo ""
        echo -e "${YELLOW}Быстрый старт при инциденте:${NC}"
        echo "  1. $0 stop       # Остановить угрозу"
        echo "  2. $0 block      # Заблокировать C2"
        echo "  3. $0 evidence   # Собрать доказательства"
        echo "  4. $0 quarantine # Удалить малварь"
        echo "  5. $0 monitor    # Включить защиту"
        echo ""
        echo "Полный отчёт: /root/eyes_cerberus/FINAL_REPORT.md"
        echo ""
        ;;
esac
