# 🏥 DICOM Router

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Orthanc](https://img.shields.io/badge/Orthanc-Integration-green.svg)](https://orthanc-server.com/)
[![HIPAA](https://img.shields.io/badge/HIPAA-Compliant-success.svg)](https://www.hhs.gov/hipaa/index.html)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

> **HIPAA-compliant маршрутизатор DICOM-изображений с веб-интерфейсом и интеграцией Orthanc**

Python-приложение для интеллектуальной маршрутизации медицинских DICOM-файлов (МРТ, КТ, рентген, УЗИ) между PACS-серверами, рабочими станциями и архивами. Поддерживает гибкие правила маршрутизации на основе модальности, DICOM-тегов и AET источника.

![Version](https://img.shields.io/badge/Version-3.5.0-blue.svg)

---

## 📋 Содержание

- [Особенности](#-особенности)
- [Архитектура](#-архитектура)
- [Быстрый старт](#-быстрый-старт)
- [Конфигурация](#-конфигурация)
- [Веб-интерфейс](#-веб-интерфейс)
- [Правила маршрутизации](#-правила-маршрутизации)
- [Безопасность](#-безопасность)
- [API Endpoints](#-api-endpoints)

---

## ✨ Особенности

### 🔒 Безопасность и Compliance

- **HIPAA Compliance** — автоматическая маскировка PHI (Protected Health Information) в логах
- **Path Traversal Protection** — защита от атак на обход директорий
- **Безопасное хранение** — проверка прав доступа к БД и файлам

### 🚀 Производительность

- **SQLite + WAL Mode** — высокая производительность записи с журналом предзаписи
- **Batch Inserts** — пакетная вставка данных для снижения нагрузки на БД
- **Circuit Breaker** — автоматическое отключение неработающих destination
- **Graceful Shutdown** — корректное завершение с обработкой pending-задач

### 🧠 Интеллектуальная маршрутизация

- **Правила на основе:**
  - Модальности (CT, MR, US, XA, etc.)
  - DICOM-тегов (StudyDescription, BodyPartExamined, etc.)
  - AET источника (Source AET)
  - Wildcard-шаблонов
- **Приоритеты правил** — гибкая система приоритетов
- **Статистика совпадений** — отслеживание использования каждого правила

### 🌐 Веб-интерфейс

- Современный UI на Bootstrap 5
- Управление правилами маршрутизации
- Мониторинг статуса и статистики
- Real-time логи
- Управление Circuit Breaker

---

## 🏗️ Архитектура

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DICOM Router v3.5.0                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌─────────────────────────────┐  │
│  │   Modality   │     │   Watch      │     │         Web UI              │  │
│  │  (CT/MR/US)  │     │   Folder     │     │   (Bootstrap 5 + REST API)  │  │
│  └──────┬───────┘     └──────┬───────┘     └─────────────────────────────┘  │
│         │                    │                                              │
│         └────────────────────┼─────────────────┐                            │
│                              ▼                 │                            │
│                    ┌──────────────────┐       │                             │
│                    │  DICOM Router    │◄──────┘                             │
│                    │  (Python/Orthanc)│                                     │
│                    └────────┬─────────┘                                     │
│                             │                                               │
│         ┌───────────────────┼───────────────────┐                           │
│         ▼                   ▼                   ▼                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐                  │
│  │   SQLite    │    │   Circuit   │    │  PHIFilter      │                  │
│  │   (WAL)     │    │   Breaker   │    │  (HIPAA logs)   │                  │
│  └─────────────┘    └─────────────┘    └─────────────────┘                  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Destinations                                │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │    │
│  │  │  EFILM  │  │  PACS   │  │  WORK   │  │  CONQ   │  │  DCM4CHE│    │    │
│  │  │  Viewer │  │  Archive│  │ Station │  │ uest    │  │  Server │    │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Быстрый старт

### Требования

- Python 3.8+
- Orthanc Server (опционально, для интеграции)
- Windows/Linux/macOS

### Установка

```bash
# Клонирование репозитория
git clone https://github.com/YOUR_USERNAME/dicom-router.git
cd dicom-router

# Установка зависимостей (если используется как standalone)
pip install -r requirements.txt
```

### Запуск

#### Вариант 1: Как плагин Orthanc

```bash
# Установите orthanc Python module
pip install orthanc

# Укажите путь к скрипту в конфигурации Orthanc
# В orthanc.json:
{
  "PythonScript": "/path/to/dicom-router.py"
}

# Запуск Orthanc
./Orthanc orthanc.json
```

#### Вариант 2: Standalone (с Watch Folder)

```bash
# Настройка переменных окружения
set ORTHANC_ROUTER_DATA=C:\dicom-router\data
set WATCH_FOLDER_PATH=C:\dicom\incoming
set WATCH_FOLDER_INTERVAL=30

# Запуск
python dicom-router.py
```

---

## ⚙️ Конфигурация

### Переменные окружения

| Переменная | Описание | Значение по умолчанию |
|------------|----------|----------------------|
| `ORTHANC_ROUTER_DATA` | Директория для данных | `./data` |
| `ORTHANC_URL` | URL Orthanc сервера | `http://localhost:8042` |
| `ORTHANC_USERNAME` | Пользователь Orthanc | - |
| `ORTHANC_PASSWORD` | Пароль Orthanc | - |
| `WATCH_FOLDER_PATH` | Путь к watch folder | - |
| `WATCH_FOLDER_INTERVAL` | Интервал сканирования (сек) | `30` |
| `WATCH_FOLDER_EXTENSIONS` | Расширения файлов | `.dcm,.bin` |
| `WATCH_FOLDER_DELETE_ORIGINALS` | Удалять исходники | `true` |
| `ORTHANC_LOG_LEVEL` | Уровень логирования | `INFO` |

### Пример конфигурации (Windows)

Создайте `orthanc-env.bat`:

```batch
@echo off
set ORTHANC_ROUTER_DATA=E:\Orthanc Server\dicom-router
set ORTHANC_URL=http://localhost:8042
set ORTHANC_USERNAME=admin
set ORTHANC_PASSWORD=your_password

set WATCH_FOLDER_PATH=E:\topacs
set WATCH_FOLDER_INTERVAL=30
set WATCH_FOLDER_EXTENSIONS=.dcm,.bin
set WATCH_FOLDER_DELETE_ORIGINALS=true

set ORTHANC_LOG_LEVEL=INFO

"E:\Orthanc Server\Orthanc.exe" orthanc.json
```

---

## 🌐 Веб-интерфейс

Веб-интерфейс доступен по адресу: `http://localhost:8042/dicom-router/index.html`

### Возможности

- **Dashboard** — общая статистика и статус системы
- **Rules** — управление правилами маршрутизации
- **Destinations** — мониторинг состояния получателей
- **Logs** — просмотр логов в реальном времени
- **Settings** — настройка системы

![Web UI Preview](docs/web-ui-preview.png)

---

## 📋 Правила маршрутизации

Правила хранятся в файле `routing-rules.json`:

```json
[
  {
    "modality": "MR",
    "destinations": ["EFILM", "PACS_MAIN"],
    "description": "МРТ-снимки → рабочие станции + архив",
    "condition_type": "tag_contains",
    "dicom_tag": "StudyDescription",
    "tag_value": "*BRAIN*",
    "source_aet": null,
    "enabled": true,
    "match_count": 1523
  },
  {
    "modality": "CT",
    "destinations": ["PACS_MAIN"],
    "description": "Все КТ → только в архив",
    "condition_type": null,
    "dicom_tag": null,
    "tag_value": null,
    "source_aet": "CT_SCANNER_01",
    "enabled": true,
    "match_count": 3421
  }
]
```

### Типы условий (`condition_type`)

| Тип | Описание | Пример |
|-----|----------|--------|
| `null` | Только по модальности | Все MR |
| `tag_equals` | Точное совпадение тега | StudyDescription = "BRAIN MRI" |
| `tag_contains` | Подстрока в теге | StudyDescription содержит "BRAIN" |
| `tag_starts_with` | Начинается с | AccessionNumber начинается с "2024" |
| `tag_regex` | Регулярное выражение | ^[0-9]{8}$ |

---

## 🔐 Безопасность

### HIPAA Compliance

- Автоматическая маскировка PHI в логах:
  - `PatientName` → `***`
  - `PatientID` → `***`
  - `AccessionNumber` → `***`
  - `PatientBirthDate` → `********`

### Защита от атак

- **Path Traversal Protection** — запрет выхода за пределы разрешённых директорий
- **Input Validation** — валидация всех входных данных
- **Permission Checks** — проверка прав доступа к файлам

### Рекомендации по безопасности

```bash
# Установите правильные права на БД (Linux/macOS)
chmod 600 dicom-router.db

# Не запускайте от root
# Используйте выделенную service account

# Используйте HTTPS для production
# Настройте firewall для ограничения доступа
```

---

## 🔌 API Endpoints

### REST API

| Endpoint                        | Метод  | Описание                 |
|---------------------------------|--------|------------------------- |
| `/api/rules`                    | GET    | Получить все правила     |
| `/api/rules`                    | POST   | Создать новое правило    |
| `/api/rules/{id}`               | PUT    | Обновить правило         |
| `/api/rules/{id}`               | DELETE | Удалить правило          |
| `/api/destinations`             | GET    | Список destination       |
| `/api/destinations/{name}/test` | POST   | Проверить соединение     |
| `/api/stats`                    | GET    | Статистика системы       |
| `/api/logs`                     | GET    | Логи (с пагинацией)      |
| `/api/circuit-breaker`          | GET    | Статус circuit breaker   |
| `/api/circuit-breaker/reset`    | POST   | Сбросить circuit breaker |

### Примеры запросов

```bash
# Получить правила
curl http://localhost:8042/api/rules

# Создать правило
curl -X POST http://localhost:8042/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "modality": "XR",
    "destinations": ["PACS_MAIN"],
    "description": "Рентген в архив",
    "enabled": true
  }'

# Проверить статистику
curl http://localhost:8042/api/stats
```

---

## 📊 Мониторинг

### Circuit Breaker Status

```json
{
  "EFILM": {
    "state": "CLOSED",
    "failures": 0
  },
  "PACS_MAIN": {
    "state": "OPEN",
    "failures": 5,
    "last_failure": "2024-01-15T10:30:00Z"
  }
}
```

**Состояния:**

- `CLOSED` — всё работает нормально
- `OPEN` — destination недоступен (блокировка на 60 сек)
- `HALF_OPEN` — тестовый режим восстановления

---

## 🤝 Contributing

1. Fork репозитория
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

---

## 📄 Лицензия

Распространяется под лицензией **GNU General Public License v3.0** (GPL-3.0).

### Что это значит

| Разрешено                     | Обязательно                                   | Запрещено                                        |
|-----------                    |-------------                                  |-----------                                       |
| ✅ Коммерческое использование | 📋 Раскрытие исходного кода                   | ❌ Сублицензирование под проприетарную лицензию  |
| ✅ Модификация                | 📋 Использование той же лицензии (GPL v3)     | ❌ Отсутствие отказа от ответственности          |
| ✅ Распространение            | 📋 Указание изменений                         |                                                  |
| ✅ Приватное использование    | 📋 Сохранение уведомления об авторских правах |                                                  |
| ✅ Патентное использование    |                                               |                                                  |

**Важно:** Если вы распространяете модифицированную версию этого ПО, вы обязаны раскрыть исходный код под той же лицензией GPL v3.

Полный текст лицензии см. в файле [LICENSE](LICENSE).

---

## 🙏 Благодарности

- [Orthanc](https://orthanc-server.com/) — лёгкий DICOM сервер
- [Bootstrap](https://getbootstrap.com/) — CSS фреймворк
- [Contributors](https://github.com/crusader3355/DicomRouterForOrthanc/graphs/contributors)

---

## 📞 Контакты

- **Issues:** [GitHub Issues](https://github.com/crusader3355/DicomRouterForOrthanc/issues)

---

<p align="center">
  <sub>Built with ❤️ for healthcare professionals</sub>
</p>
