from __future__ import annotations

import json
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "botsv1.json"
OUTPUT_DIR = BASE_DIR / "output"


def flatten_value(value):
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return value


def parse_timestamp(df: pd.DataFrame) -> pd.Series:
    month_map = {
        "january": "01",
        "february": "02",
        "march": "03",
        "april": "04",
        "may": "05",
        "june": "06",
        "july": "07",
        "august": "08",
        "september": "09",
        "october": "10",
        "november": "11",
        "december": "12",
    }

    year = df.get("date_year", "").astype(str).str.strip()
    month = df.get("date_month", "").astype(str).str.lower().map(month_map).fillna("01")
    day = df.get("date_mday", "").astype(str).str.zfill(2)
    hour = df.get("date_hour", "").astype(str).str.zfill(2)
    minute = df.get("date_minute", "").astype(str).str.zfill(2)
    second = df.get("date_second", "").astype(str).str.zfill(2)

    ts = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second
    return pd.to_datetime(ts, errors="coerce")


def load_data(path: Path) -> pd.DataFrame:
    with open(path, "r", encoding="utf-8") as file:
        raw_data = json.load(file)

    records = [item.get("result", item) for item in raw_data]
    df = pd.json_normalize(records)

    for column in df.columns:
        df[column] = df[column].apply(flatten_value)

    df = df.copy()
    df["EventCode"] = df.get("EventCode", "").astype(str)
    df["timestamp"] = parse_timestamp(df)
    df["host"] = df.get("ComputerName", df.get("host", ""))
    return df


def get_basename(path_value: str) -> str:
    if pd.isna(path_value) or not str(path_value).strip():
        return "unknown"
    return str(path_value).replace("/", "\\").split("\\")[-1]


def detect_suspicious_winevents(df: pd.DataFrame) -> pd.DataFrame:
    win = df[df["LogName"].astype(str).eq("Security")].copy()

    win["process_name"] = win["New_Process_Name"].fillna("")
    missing_mask = win["process_name"].astype(str).str.strip().eq("")
    win.loc[missing_mask, "process_name"] = win.loc[missing_mask, "Process_Name"].fillna("")
    win["process_base"] = win["process_name"].apply(get_basename)

    suspicious_create = {"splunk-powershell.exe", "splunk-MonitorNoHandle.exe"}
    suspicious_exit = {"splunk-powershell.exe", "splunk-regmon.exe", "splunk-MonitorNoHandle.exe"}

    def classify(row: pd.Series) -> tuple[bool, str, str, str]:
        event_code = str(row.get("EventCode", ""))
        process_base = get_basename(row.get("process_name", ""))
        exit_status = str(row.get("Exit_Status", "")).strip()
        logon_type = str(row.get("Logon_Type", "")).strip()
        auth_package = str(row.get("Authentication_Package", "")).strip()

        if event_code == "4703":
            category = "WinEventLog: privilege escalation / user rights changed"
            label = f"4703: User right adjusted ({process_base})"
            reason = "Возможная эскалация привилегий: изменены пользовательские права."
            return True, category, label, reason

        if event_code == "4688" and process_base in suspicious_create:
            category = "WinEventLog: suspicious process creation"
            label = f"4688: New process created ({process_base})"
            reason = "Запуск PowerShell или скрытого сервисного процесса требует проверки."
            return True, category, label, reason

        if event_code == "4689" and (process_base in suspicious_exit or exit_status.lower() == "0x1"):
            category = "WinEventLog: suspicious process termination"
            suffix = f", exit {exit_status}" if exit_status else ""
            label = f"4689: Process exited ({process_base}{suffix})"
            reason = "Завершение сервисного процесса с кодом 0x1 требует проверки."
            return True, category, label, reason

        if event_code == "4624" and logon_type == "3":
            category = "WinEventLog: remote network logon"
            label = f"4624: Remote network logon ({auth_package or 'unknown auth'})"
            reason = "Сетевой вход типа 3 может быть признаком удалённой активности."
            return True, category, label, reason

        if event_code == "4656":
            category = "WinEventLog: suspicious object access"
            label = f"4656: Object handle request ({process_base})"
            reason = "Запрос дескриптора к объекту файловой системы требует дополнительной проверки."
            return True, category, label, reason

        return False, "", "", ""

    classified = win.apply(classify, axis=1, result_type="expand")
    classified.columns = ["is_suspicious", "SuspiciousCategory", "SuspiciousLabel", "SuspiciousReason"]
    win = pd.concat([win, classified], axis=1)
    win = win[win["is_suspicious"]].copy()

    selected_columns = [
        "timestamp",
        "host",
        "EventCode",
        "TaskCategory",
        "process_name",
        "Process_Command_Line",
        "Logon_Type",
        "Authentication_Package",
        "Source_Network_Address",
        "Exit_Status",
        "SuspiciousCategory",
        "SuspiciousLabel",
        "SuspiciousReason",
        "body",
    ]
    selected_columns = [column for column in selected_columns if column in win.columns]
    return win[selected_columns].sort_values(["timestamp", "EventCode"]).reset_index(drop=True)


def looks_random_domain(domain: str) -> bool:
    domain = str(domain).lower().strip()
    first_label = domain.split(".")[0]
    has_digits = any(char.isdigit() for char in first_label)
    mostly_consonants = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{4,}", first_label))
    long_mixed_label = len(first_label) >= 8 and has_digits
    return long_mixed_label or mostly_consonants


def detect_suspicious_dns(df: pd.DataFrame) -> pd.DataFrame:
    dns = df[(df["LogName"].astype(str).eq("DNS")) | (df["app"].astype(str).eq("dns"))].copy()
    dns["domain"] = dns.get("QueryName", "").astype(str).str.lower()
    dns["subdomain_depth"] = dns["domain"].str.count(r"\.") + 1
    dns["eventtype_text"] = dns.get("eventtype", "").astype(str).str.lower()

    categories = []
    labels = []
    reasons = []
    suspicious_flags = []

    for _, row in dns.iterrows():
        domain = row.get("domain", "")
        body = str(row.get("body", "")).lower()
        eventtype_text = str(row.get("eventtype_text", "")).lower()

        if "beacon" in body or "beacon" in eventtype_text or "c2" in domain or "malicious" in domain:
            categories.append("DNS: possible C2 / beaconing")
            labels.append(f"DNS: Possible C2/beaconing ({domain})")
            reasons.append("Похоже на C2-активность или DNS-beaconing.")
            suspicious_flags.append(True)
        elif looks_random_domain(domain):
            categories.append("DNS: random-looking or rare domain")
            labels.append(f"DNS: Random-looking domain ({domain})")
            reasons.append("Домен выглядит случайным или DGA-подобным.")
            suspicious_flags.append(True)
        elif row.get("subdomain_depth", 0) >= 4:
            categories.append("DNS: deep subdomain chain")
            labels.append(f"DNS: Deep subdomain chain ({domain})")
            reasons.append("Слишком длинная цепочка поддоменов может быть аномальной.")
            suspicious_flags.append(True)
        else:
            categories.append("")
            labels.append("")
            reasons.append("")
            suspicious_flags.append(False)

    dns["is_suspicious"] = suspicious_flags
    dns["SuspiciousCategory"] = categories
    dns["SuspiciousLabel"] = labels
    dns["SuspiciousReason"] = reasons
    dns = dns[dns["is_suspicious"]].copy()

    selected_columns = [
        "timestamp",
        "host",
        "QueryName",
        "QueryType",
        "ClientIP",
        "ResponseCode",
        "SuspiciousCategory",
        "SuspiciousLabel",
        "SuspiciousReason",
        "body",
    ]
    selected_columns = [column for column in selected_columns if column in dns.columns]
    return dns[selected_columns].sort_values("timestamp").reset_index(drop=True)


def build_top10(winevents: pd.DataFrame, dns: pd.DataFrame) -> pd.DataFrame:
    combined = pd.concat(
        [
            winevents[["SuspiciousCategory"]].rename(columns={"SuspiciousCategory": "Category"}),
            dns[["SuspiciousCategory"]].rename(columns={"SuspiciousCategory": "Category"}),
        ],
        ignore_index=True,
    )

    top10 = (
        combined.groupby("Category")
        .size()
        .reset_index(name="Count")
        .sort_values(["Count", "Category"], ascending=[False, True])
        .head(10)
        .reset_index(drop=True)
    )
    return top10


def save_plot(top10: pd.DataFrame, output_path: Path) -> None:
    plt.figure(figsize=(12, 7))
    plt.barh(top10["Category"][::-1], top10["Count"][::-1])
    plt.xlabel("Количество событий")
    plt.ylabel("Категория")
    plt.title("Топ подозрительных событий в WinEventLog и DNS")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = load_data(DATA_PATH)
    winevents = detect_suspicious_winevents(df)
    dns = detect_suspicious_dns(df)
    top10 = build_top10(winevents, dns)

    winevents.to_csv(OUTPUT_DIR / "suspicious_wineventlog.csv", index=False, encoding="utf-8-sig")
    dns.to_csv(OUTPUT_DIR / "suspicious_dns.csv", index=False, encoding="utf-8-sig")
    top10.to_csv(OUTPUT_DIR / "top10_suspicious_events.csv", index=False, encoding="utf-8-sig")
    save_plot(top10, OUTPUT_DIR / "top10_suspicious_events.png")

    summary_lines = [
        f"Всего записей: {len(df)}",
        f"Подозрительных WinEventLog: {len(winevents)}",
        f"Подозрительных DNS: {len(dns)}",
        "",
        "Топ подозрительных категорий:",
    ]
    for _, row in top10.iterrows():
        summary_lines.append(f"- {row['Category']}: {row['Count']}")

    (OUTPUT_DIR / "summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")
    print("\n".join(summary_lines))


if __name__ == "__main__":
    main()
