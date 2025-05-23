```markdown
# Trivy Prometheus Exporter

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)

Экспортер для преобразования отчетов Trivy в метрики Prometheus. Собирает данные из JSON-отчетов и предоставляет их в формате, пригодном для мониторинга в Prometheus.

## 🚀 Особенности

- Поддержка сканирований:
  - **Образы Docker**: Уязвимости и секреты
  - **Kubernetes-кластеры**: Конфигурационные ошибки
  - **RBAC-оценки**: Роли и ClusterRoles
- Метрики:
  - Уязвимости по уровню критичности (CRITICAL, HIGH, MEDIUM, LOW)
  - Обнаруженные секреты в образах
  - Ошибки конфигурации ресурсов
  - Проблемы RBAC-политик
- Автоматическое обновление метрик при появлении новых отчетов

## 📦 Установка

1. Клонировать репозиторий:
```bash
git clone https://github.com/FedAnt/trivy-prometheus-exporter.git
cd trivy-prometheus-exporter
```

2. Собрать образ:
```bash
docker build -t trivy-exporter .
```

3. Запустить экспортер
```bash
docker run -d \
    -p 8000:8000 \
    -v /home/user/trivy-prometheus-exporter/json:/scans \
    -e TRIVY_SCAN_DIR=/scans \
    -e EXPORTER_PORT=8000 \
    -e LOG_LEVEL=ERROR \
    --name trivy-prometheus-exporter \
    trivy-prometheus-exporter
```

## ⚙️ Конфигурация

### Переменные окружения

| Переменная              | По умолчанию      | Описание                          |
|-------------------------|-------------------|-----------------------------------|
| `TRIVY_SCAN_DIR`        | `/scans`          | Директория для отчетов Trivy      |
| `EXPORTER_PORT`         | `8000`            | Порт HTTP-сервера                 |
| `EXPORTER_HOST`         | `0.0.0.0`         | Хост для прослушивания            |
| `LOG_LEVEL`             | `INFO`            | Уровень логирования (DEBUG/INFO)  |

Создайте файл `.env` для локальной настройки:
```ini
TRIVY_SCAN_DIR=/path/to/scans
LOG_LEVEL=DEBUG
```

## 🖥 Использование

### Запуск экспортера
```bash
python main.py
```

### Проверка работоспособности
```bash
curl http://localhost:8000/health
# OK

curl http://localhost:8000/metrics
# trivy_image_vulnerabilities{severity="HIGH",...} 12
```

## 🔄 Интеграция с Trivy

Пример команды для сканирования образа:
```bash
trivy image --format json -o /scans/image_scan.json your-image:tag
```

Для Kubernetes-кластера:
```bash
trivy k8s --format json -o /scans/cluster_scan.json cluster
```

## 📊 Настройка Prometheus

Добавьте в `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'trivy-prometheus-exporter'
    static_configs:
      - targets: ['exporter-host:8000']
```

## 📊 Настройка Grafana

Импортирейте дашборд `Trivy_Workload Vulnerabilities.json`

## 📈 Пример метрик

```prometheus
# Уязвимости образов
trivy_image_vulnerabilities{severity="CRITICAL", image_repository="nginx", namespace="debian"} 3

# Секреты в образах
trivy_image_exposedsecrets{image_repository="redis", image_tag="6.2"} 2

# Ошибки конфигурации
trivy_resource_configaudits{severity="HIGH", namespace="default"} 5
```

## Workflow для CI/CD

Пример пайплайна для jenkins можно посмотреть в файле `pipelineTrivyImageScanner.groovy`

## 🛠 Разработка

### Тестирование
```bash
TODO
```

### Форматирование кода
```bash
TODO
```

## 📄 Лицензия

MIT License. Подробнее в файле [![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT).

---
