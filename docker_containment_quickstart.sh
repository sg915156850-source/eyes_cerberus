#!/bin/bash
#===============================================================================
# SYSTEM EYES - DOCKER CONTAINMENT QUICK START
# Быстрый старт изоляции вредоносов в Docker
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}     SYSTEM EYES - DOCKER CONTAINMENT QUICK START      ${BLUE}║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Проверка Docker
echo -e "${YELLOW}[1/5]${NC} Проверка Docker..."
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    echo -e "  ${GREEN}✓${NC} Docker установлен: $DOCKER_VERSION"
else
    echo -e "  ${RED}✗${NC} Docker НЕ найден!"
    echo ""
    echo "  Для установки выполните:"
    echo "    curl -fsSL https://get.docker.com | sh"
    echo ""
    exit 1
fi

# Проверка прав доступа
echo -e "${YELLOW}[2/5]${NC} Проверка прав доступа..."
if docker ps &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} Права доступа OK"
else
    echo -e "  ${RED}✗${NC} Нет прав доступа к Docker!"
    echo ""
    echo "  Добавьте пользователя в группу docker:"
    echo "    sudo usermod -aG docker \$USER"
    echo "    # Затем выйдите и войдите снова"
    echo ""
    exit 1
fi

# Проверка доступности скрипта
echo -e "${YELLOW}[3/5]${NC} Проверка скрипта изоляции..."
if [ -f "/root/eyes_cerberus/containment.sh" ]; then
    echo -e "  ${GREEN}✓${NC} Скрипт найден"
else
    echo -e "  ${RED}✗${NC} Скрипт НЕ найден!"
    exit 1
fi

# Проверка малвари
echo -e "${YELLOW}[4/5]${NC} Проверка файлов малвари..."
MALWARE_COUNT=0
for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
    if [ -f "$f" ]; then
        MALWARE_COUNT=$((MALWARE_COUNT + 1))
    fi
done

if [ "$MALWARE_COUNT" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} Найдено файлов малвари: $MALWARE_COUNT"
else
    echo -e "  ${GREEN}✓${NC} Файлов малвари не найдено"
fi

# Статус контейнера
echo -e "${YELLOW}[5/5]${NC} Проверка существующих контейнеров..."
EXISTING=$(docker ps -a --format '{{.Names}}' | grep -c malware_sandbox || echo "0")
if [ "$EXISTING" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} Найден существующий контейнер изоляции"
    docker ps -a --format 'table {{.Names}}\t{{.Status}}' | grep malware_sandbox
else
    echo -e "  ${GREEN}✓${NC} Существующих контейнеров нет"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

# Меню
echo "Выберите действие:"
echo ""
echo "  ${GREEN}1${NC}) Запустить изоляцию малвари"
echo "  ${YELLOW}2${NC}) Проверить статус"
echo "  ${BLUE}3${NC}) Показать логи"
echo "  ${RED}4${NC}) Остановить контейнер"
echo "  ${RED}5${NC}) Удалить контейнер"
echo "  ${RED}0${NC}) Выход"
echo ""
read -p "Ваш выбор: " choice

case $choice in
    1)
        echo ""
        echo -e "${YELLOW}Запуск изоляции...${NC}"
        echo ""
        /root/eyes_cerberus/containment.sh setup
        ;;
    2)
        echo ""
        /root/eyes_cerberus/containment.sh status
        ;;
    3)
        echo ""
        /root/eyes_cerberus/containment.sh logs
        ;;
    4)
        echo ""
        /root/eyes_cerberus/containment.sh stop
        ;;
    5)
        echo ""
        /root/eyes_cerberus/containment.sh remove
        ;;
    0)
        echo "Выход"
        exit 0
        ;;
    *)
        echo "Неверный выбор"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Готово!${NC}"
echo ""
