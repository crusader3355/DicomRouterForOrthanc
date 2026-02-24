@echo off
REM Основные настройки
set ORTHANC_ROUTER_DATA=E:\Orthanc Server\dicom-router
set ORTHANC_URL=http://localhost:8042
set ORTHANC_USERNAME=admin
set ORTHANC_PASSWORD=12qwAS

REM Watch Folder настройки
set WATCH_FOLDER_PATH=E:\topacs
set WATCH_FOLDER_INTERVAL=30
set WATCH_FOLDER_EXTENSIONS=.dcm,.bin
set WATCH_FOLDER_DELETE_ORIGINALS=true
set WATCH_FOLDER_CLEANUP_ENABLED=true
set WATCH_FOLDER_CLEANUP_INTERVAL=3600

REM Логирование
set ORTHANC_LOG_LEVEL=INFO

REM Запуск Orthanc
"E:\Orthanc Server\Orthanc.exe" orthanc.json