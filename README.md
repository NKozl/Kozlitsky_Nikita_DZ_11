# Домашнее задание №11  
**Тема:** Python для аналитиков ИБ: поиск негативных событий

## Структура проекта
```text
ib_python_hw11/
├── analyze_logs.py
├── README.md
├── requirements.txt
├── .gitignore
├── data/
│   └── botsv1.json
└── output/
    ├── suspicious_wineventlog.csv
    ├── suspicious_dns.csv
    ├── top10_suspicious_events.csv
    ├── top10_suspicious_events.png
    └── summary.txt
```

## Используемые библиотеки
- pandas
- matplotlib
- seaborn

## Как запустить
```bash
pip install -r requirements.txt
python analyze_logs.py
```

После запуска скрипт автоматически создаст папку `output/` и сохранит туда результаты анализа.

## Логика поиска подозрительных событий

### WinEventLog
Подозрительными считаются события:

- **4703** — изменение пользовательских прав, возможная эскалация привилегий;
- **4688** — создание подозрительного процесса (`splunk-powershell.exe`, `splunk-MonitorNoHandle.exe`);
- **4689** — завершение подозрительных процессов или завершение с кодом `0x1`;
- **4624** с `Logon_Type = 3` — удалённый сетевой вход;
- **4656** — запрос дескриптора к объекту файловой системы.

### DNS
Подозрительными считаются запросы:

- к доменам, похожим на случайно сгенерированные;
- к доменам с признаками **C2 / beaconing**;
- к аномально длинным цепочкам поддоменов.
