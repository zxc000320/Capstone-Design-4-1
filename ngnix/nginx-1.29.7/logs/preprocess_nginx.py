import pandas as pd
import os
import re

log_paths = [
    "lb_access.log",
    "access.log",
    "C:/ngnix/nginx-1.29.7/logs/lb_access.log",
    "C:/ngnix/nginx-1.29.7/logs/access.log"
]

log_file = None

for path in log_paths:
    if os.path.exists(path):
        log_file = path
        break

if log_file is None:
    raise FileNotFoundError("로그 파일을 찾을 수 없습니다.")

data = []

pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d+) '
    r'upstream=(?P<server>\S+)'
)

with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = pattern.search(line)
        if not match:
            continue

        try:
            time_raw = match.group("time")
            time = time_raw.split(":")[1] + ":" + time_raw.split(":")[2]

            status = int(match.group("status"))
            server = match.group("server")

            response_time = 1

            data.append([time, server, response_time, status])

        except:
            continue

df = pd.DataFrame(data, columns=["time", "server", "response_time", "status"])

df["time"] = df["time"].str[:5]
df["error"] = df["status"] >= 500

basic = df.groupby(["time", "server"]).agg(
    request_count=("time", "count"),
    avg_response_time=("response_time", "mean"),
    error_rate=("error", "mean")
).reset_index()

extra = df.groupby(["time", "server"]).agg(
    max_response_time=("response_time", "max"),
    min_response_time=("response_time", "min"),
    success_rate=("error", lambda x: 1 - x.mean())
).reset_index()

final = pd.merge(basic, extra, on=["time", "server"])

csv_path = "C:/ngnix/nginx-1.29.7/logs/processed_data.csv"
final.to_csv(csv_path, index=False)

print(f"사용된 로그 파일: {log_file}")
print(final)
print(f"CSV 저장 경로: {csv_path}")
print("전처리 완료")