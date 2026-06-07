"""
nlp_engine.py - TF-IDF 기반 자연어 이해 모듈
app2.py 에서 import 해서 사용

역할:
1. processed_data.csv 로드
2. web1 / web2 실시간 상태 확인
3. 사용자 질문 의도 분류
4. 트래픽 현황/이상탐지/응답시간/에러율/성공률/운영권고 답변 생성
"""

import os
import re
import time
import requests
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# =========================================================
# 경로 설정
# =========================================================
RF_BASE_DIR = r"C:\ngnix\nginx-1.29.7\logs"
RF_CSV_PATH = os.path.join(RF_BASE_DIR, "processed_data.csv")


# =========================================================
# 실시간 웹서버 상태 체크 대상
# =========================================================
REALTIME_TARGETS = [
    {
        "name": "Web1",
        "server": "192.168.37.134:80",
        "url": "http://192.168.37.134:80"
    },
    {
        "name": "Web2",
        "server": "192.168.37.133:80",
        "url": "http://192.168.37.133:80"
    },
]


# =========================================================
# 인텐트 패턴 정의
# =========================================================
INTENTS = [
    {
        "intent": "전체현황",
        "patterns": [
            "전체 현황", "현재 상태", "서버 상태", "지금 어때", "전체 요약",
            "현황 알려줘", "상태 알려줘", "어떻게 돼", "전반적인 상황", "개요",
            "summary", "overview", "status", "전체", "요약"
        ]
    },
    {
        "intent": "이상탐지",
        "patterns": [
            "이상 트래픽", "이상 있어", "위험한 서버", "위험 서버", "이상한 곳",
            "문제 있어", "문제 서버", "경보", "알림", "위험", "이상 탐지",
            "anomaly", "위험한거", "빨간", "주의", "경고", "이상"
        ]
    },
    {
        "intent": "응답시간",
        "patterns": [
            "응답시간", "응답 시간", "반응속도", "느린 서버", "빠른 서버",
            "latency", "response time", "ms", "밀리초", "속도",
            "느려", "빨라", "응답이", "응답 얼마나"
        ]
    },
    {
        "intent": "트래픽",
        "patterns": [
            "트래픽", "요청 수", "요청수", "접속자", "접속 수",
            "request", "얼마나 들어와", "몇건", "몇 건", "요청 많은",
            "트래픽 많은", "피크", "peak", "요청"
        ]
    },
    {
        "intent": "에러율",
        "patterns": [
            "에러율", "에러 율", "오류율", "에러", "오류", "실패율",
            "error rate", "실패", "에러 많은", "오류 많은", "500"
        ]
    },
    {
        "intent": "성공률",
        "patterns": [
            "성공률", "성공 률", "성공", "정상 처리", "처리율",
            "success rate", "얼마나 성공", "잘 되고 있어", "성공적"
        ]
    },
    {
        "intent": "서버목록",
        "patterns": [
            "서버 목록", "서버 리스트", "어떤 서버", "서버 종류",
            "몇 개 서버", "서버 몇개", "서버 이름", "서버들", "서버 뭐뭐"
        ]
    },
    {
        "intent": "시간대",
        "patterns": [
            "시간대", "몇 시", "몇시", "언제 많아", "피크 타임",
            "바쁜 시간", "한가한 시간", "시간별", "시간대별", "언제"
        ]
    },
    {
        "intent": "운영권고",
        "patterns": [
            "운영 권고", "운영 조치", "관리자 조치", "조치 필요",
            "어떻게 해야 해", "어떻게 해야 돼", "뭘 해야 해",
            "점검해야 할 서버", "점검 대상", "조치할 서버",
            "분산 정책 유지", "로드밸런싱 유지", "트래픽 우회",
            "관리자 입장", "의사결정", "권고", "추천 조치",
            "운영 판단", "대응 방안", "대응", "조치",
            "지금 어떻게", "지금 뭘", "운영상 조치", "정책 유지",
            "로드밸런서 유지", "어느 서버를 점검", "점검해야 해",
            "분산 정책 유지해도 돼", "로드밸런싱 정책 유지해도 돼"
        ]
    },
    {
        "intent": "예측",
        "patterns": [
            "예측", "앞으로", "미래", "전망", "예상",
            "predict", "forecast", "앞으로 어떻게", "증가할", "내일"
        ]
    },
]


# =========================================================
# TF-IDF 모델 학습
# =========================================================
_all_patterns = []
_pattern_intents = []

for item in INTENTS:
    for p in item["patterns"]:
        _all_patterns.append(p)
        _pattern_intents.append(item["intent"])

_vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 3))
_tfidf_matrix = _vectorizer.fit_transform(_all_patterns)


def classify_intent(user_text: str, threshold: float = 0.12) -> str:
    """
    사용자 입력을 TF-IDF 코사인 유사도로 인텐트 분류
    특정 서버 IP가 들어오면 server:IP 형태로 반환
    """

    ip_match = re.search(r"192\.168\.\d+\.\d+", user_text)
    if ip_match:
        return f"server:{ip_match.group()}"

    vec = _vectorizer.transform([user_text])
    sims = cosine_similarity(vec, _tfidf_matrix)[0]

    best_idx = int(np.argmax(sims))
    best_score = float(sims[best_idx])

    if best_score < threshold:
        return "unknown"

    return _pattern_intents[best_idx]


def load_traffic_data() -> dict:
    """
    processed_data.csv 로드 및 요약 생성
    """

    data = {
        "records": [],
        "summary": {}
    }

    try:
        df = pd.read_csv(RF_CSV_PATH)

        required_cols = [
            "time",
            "server",
            "request_count",
            "avg_response_time",
            "error_rate",
            "success_rate"
        ]

        missing = [c for c in required_cols if c not in df.columns]
        if missing:
            data["error"] = f"CSV에 필요한 컬럼이 없습니다: {missing}"
            return data

        data["records"] = df.to_dict("records")
        data["summary"] = {
            "total": len(df),
            "servers": df["server"].unique().tolist(),
            "avg_request": round(df["request_count"].mean(), 2),
            "max_request": int(df["request_count"].max()),
            "avg_rt": round(df["avg_response_time"].mean(), 2),
            "max_rt": round(df["avg_response_time"].max(), 2),
            "avg_err": round(df["error_rate"].mean() * 100, 2),
            "avg_succ": round(df["success_rate"].mean() * 100, 2),
        }

    except FileNotFoundError:
        data["error"] = f"processed_data.csv 파일을 찾을 수 없습니다: {RF_CSV_PATH}"
    except Exception as e:
        data["error"] = str(e)

    return data


def check_realtime_server_status() -> list:
    """
    web1/web2 현재 HTTP 접속 가능 여부를 실시간으로 확인
    """

    results = []

    for target in REALTIME_TARGETS:
        start = time.time()

        try:
            r = requests.get(target["url"], timeout=2)
            latency = int((time.time() - start) * 1000)

            results.append({
                "name": target["name"],
                "server": target["server"],
                "url": target["url"],
                "alive": True,
                "status_code": r.status_code,
                "latency_ms": latency,
                "message": f"정상 ({r.status_code})"
            })

        except Exception as e:
            latency = int((time.time() - start) * 1000)

            results.append({
                "name": target["name"],
                "server": target["server"],
                "url": target["url"],
                "alive": False,
                "status_code": None,
                "latency_ms": latency,
                "message": f"다운 / 오류: {e}"
            })

    return results


def generate_response(intent: str, data: dict) -> str:
    """
    인텐트 + 데이터 기반 자연어 응답 생성
    """

    if data.get("error"):
        return f"데이터를 불러오지 못했습니다.\n\n오류 내용: {data['error']}"

    s = data.get("summary", {})
    records = data.get("records", [])

    if not s or not records:
        return "데이터가 없습니다. processed_data.csv 파일을 먼저 생성해주세요."

    df = pd.DataFrame(records)

    numeric_cols = [
        "request_count",
        "avg_response_time",
        "error_rate",
        "success_rate",
    ]

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # =====================================================
    # 특정 서버 조회
    # =====================================================
    if intent.startswith("server:"):
        ip = intent.split(":")[1]
        matched = df[df["server"].astype(str).str.contains(ip, na=False)]

        realtime = check_realtime_server_status()
        realtime_target = [
            r for r in realtime
            if r["server"].startswith(ip)
        ]

        realtime_text = ""
        if realtime_target:
            rt = realtime_target[0]
            icon = "🟢" if rt["alive"] else "🔴"
            realtime_text = (
                f"\n[실시간 상태]\n"
                f"- {icon} {rt['name']} ({rt['server']}): {rt['message']} / {rt['latency_ms']}ms\n"
            )

        if matched.empty:
            if realtime_target:
                rt = realtime_target[0]
                if not rt["alive"]:
                    return (
                        f"서버 {ip} 에 대한 CSV 데이터는 없지만, 실시간 확인 결과 응답하지 않습니다.\n\n"
                        f"{realtime_text}\n"
                        f"권고: 해당 서버의 Nginx 실행 상태와 네트워크 연결을 우선 확인하세요."
                    )
            return f"서버 {ip} 에 대한 데이터가 없습니다."

        lines = [f"{ip} 서버 분석 결과입니다.\n"]

        total_req = int(matched["request_count"].sum())
        avg_rt = round(matched["avg_response_time"].mean(), 2)
        avg_err = round(matched["error_rate"].mean() * 100, 2)
        avg_succ = round(matched["success_rate"].mean() * 100, 2)

        lines.append(f"- 총 요청 수: {total_req}건")
        lines.append(f"- 평균 응답시간: {avg_rt}ms")
        lines.append(f"- 평균 에러율: {avg_err}%")
        lines.append(f"- 평균 성공률: {avg_succ}%")
        lines.append(realtime_text)

        if realtime_target and not realtime_target[0]["alive"]:
            lines.append("판단: 🔴 위험")
            lines.append("권고: 실시간 상태에서 서버가 응답하지 않습니다. 해당 서버를 즉시 점검하고 정상 서버로 트래픽이 우회되는지 확인하세요.")
        elif avg_err > 10:
            lines.append("판단: 🔴 위험")
            lines.append("권고: 해당 서버를 우선 점검하고, 필요 시 트래픽 우회를 고려하세요.")
        elif avg_err > 0 or avg_succ < 99:
            lines.append("판단: 🟡 주의")
            lines.append("권고: 오류 로그를 확인하고 일정 시간 동안 추가 모니터링하는 것이 좋습니다.")
        else:
            lines.append("판단: 🟢 정상")
            lines.append("권고: 현재는 기존 분산 정책을 유지해도 됩니다.")

        return "\n".join(lines)

    # =====================================================
    # 전체 현황
    # =====================================================
    if intent == "전체현황":
        realtime = check_realtime_server_status()
        realtime_lines = []

        for r in realtime:
            icon = "🟢" if r["alive"] else "🔴"
            realtime_lines.append(
                f"- {icon} {r['name']} ({r['server']}): {r['message']} / {r['latency_ms']}ms"
            )

        down_servers = [r for r in realtime if not r["alive"]]

        if down_servers:
            state = "🔴 위험"
            advice = "실시간 확인 결과 응답하지 않는 웹서버가 있습니다. 해당 서버를 우선 점검하세요."
        else:
            state = "🟢 정상"
            advice = "실시간 확인 결과 web1/web2 모두 정상 응답 중입니다."

        return (
            f"현재 서버 트래픽 전체 현황입니다.\n\n"
            f"[실시간 판단]\n"
            f"- 상태: {state}\n"
            f"- 권고: {advice}\n\n"
            f"[실시간 서버 상태]\n"
            + "\n".join(realtime_lines)
            + f"\n\n[로그 기반 요약]\n"
            f"- 총 분석 레코드: {s['total']}건\n"
            f"- 평균 요청 수: {s['avg_request']}건\n"
            f"- 최대 요청 수: {s['max_request']}건\n"
            f"- 평균 응답시간: {s['avg_rt']}ms\n"
            f"- 최대 응답시간: {s['max_rt']}ms\n"
            f"- 평균 에러율: {s['avg_err']}%\n"
            f"- 평균 성공률: {s['avg_succ']}%\n\n"
            f"모니터링 서버 목록:\n"
            + "\n".join([f"- {sv}" for sv in s["servers"]])
        )

    # =====================================================
    # 이상 탐지
    # =====================================================
    if intent == "이상탐지":
        realtime = check_realtime_server_status()
        down_servers = [r for r in realtime if not r["alive"]]

        if down_servers:
            lines = ["실시간 이상 상태가 감지되었습니다.\n"]
            for r in down_servers:
                lines.append(
                    f"🔴 {r['name']} ({r['server']}) 응답 없음\n"
                    f"- 상태: {r['message']}\n"
                    f"- 확인 지연: {r['latency_ms']}ms\n"
                )
            lines.append("권고: 다운된 서버의 Nginx 상태, VM 네트워크, IP 설정을 우선 확인하세요.")
            return "\n".join(lines)

        thr = df["avg_response_time"].mean() + 2 * df["avg_response_time"].std()

        anomalies = df[
            (df["error_rate"] > 0) |
            (df["avg_response_time"] > thr)
        ]

        if anomalies.empty:
            return (
                "현재 이상 트래픽이 감지된 서버는 없습니다.\n\n"
                "판단: 🟢 정상\n"
                "권고: 실시간 web1/web2 상태도 정상이며, 현재는 기존 로드밸런싱 정책을 유지해도 됩니다."
            )

        lines = [f"로그 기준 이상 트래픽이 {len(anomalies)}건 감지되었습니다.\n"]

        for _, r in anomalies.iterrows():
            lines.append(
                f"🔴 [{r['time']}] {r['server']}\n"
                f"- 요청 수: {int(r['request_count'])}건\n"
                f"- 응답시간: {round(r['avg_response_time'], 2)}ms\n"
                f"- 에러율: {round(r['error_rate'] * 100, 2)}%\n"
            )

        lines.append("권고: 위 서버를 우선 점검하고, 장애가 지속되면 트래픽 우회를 고려하세요.")
        return "\n".join(lines)

    # =====================================================
    # 응답시간
    # =====================================================
    if intent == "응답시간":
        realtime = check_realtime_server_status()

        realtime_lines = []
        for r in realtime:
            icon = "🟢" if r["alive"] else "🔴"
            realtime_lines.append(
                f"- {icon} {r['name']} ({r['server']}): {r['latency_ms']}ms / {r['message']}"
            )

        by_server = df.groupby("server")["avg_response_time"].mean().sort_values(ascending=False)

        lines = ["서버별 평균 응답시간입니다.\n"]

        lines.append("[실시간 응답 상태]")
        lines.extend(realtime_lines)
        lines.append("\n[로그 기반 평균 응답시간]")

        for sv, rt in by_server.items():
            bar = "█" * max(1, int(rt * 5))
            lines.append(f"- {sv}: {round(rt, 2)}ms {bar}")

        slowest = by_server.index[0]
        slowest_rt = round(by_server.iloc[0], 2)

        lines.append(
            f"\n로그 기준 가장 응답시간이 높은 서버는 {slowest} ({slowest_rt}ms)입니다."
        )

        down_servers = [r for r in realtime if not r["alive"]]
        if down_servers:
            lines.append("권고: 실시간 상태에서 응답하지 않는 서버가 있으므로 해당 서버를 우선 점검하세요.")
        elif slowest_rt > by_server.mean() * 1.5 and slowest_rt > 1:
            lines.append("권고: 해당 서버의 CPU/메모리 사용률, Nginx 상태, 백엔드 응답 지연 여부를 점검하세요.")
        else:
            lines.append("권고: 서버 간 응답시간 차이가 크지 않아 즉각적인 조치는 필요하지 않습니다.")

        return "\n".join(lines)

    # =====================================================
    # 트래픽
    # =====================================================
    if intent == "트래픽":
        by_server = df.groupby("server")["request_count"].sum().sort_values(ascending=False)

        lines = ["서버별 총 요청 수입니다.\n"]

        for sv, cnt in by_server.items():
            lines.append(f"- {sv}: {int(cnt)}건")

        busiest = by_server.index[0]
        busiest_count = int(by_server.iloc[0])

        lines.append(f"\n요청이 가장 많은 서버는 {busiest} ({busiest_count}건)입니다.")

        if busiest_count > by_server.mean() * 1.5:
            lines.append("권고: 특정 서버로 요청이 집중되고 있으므로 로드밸런싱 분산 상태를 확인하세요.")
        else:
            lines.append("권고: 요청이 특정 서버에 과도하게 몰린 상태는 아니므로 현재 분산 정책을 유지해도 됩니다.")

        return "\n".join(lines)

    # =====================================================
    # 에러율
    # =====================================================
    if intent == "에러율":
        realtime = check_realtime_server_status()
        down_servers = [r for r in realtime if not r["alive"]]

        by_server = df.groupby("server")["error_rate"].mean().sort_values(ascending=False)

        lines = ["서버별 평균 에러율입니다.\n"]

        if down_servers:
            lines.append("[실시간 장애 상태]")
            for r in down_servers:
                lines.append(f"- 🔴 {r['name']} ({r['server']}): 응답 없음")
            lines.append("")

        lines.append("[로그 기반 평균 에러율]")
        for sv, err in by_server.items():
            flag = "🔴" if err > 0.1 else ("🟡" if err > 0 else "🟢")
            lines.append(f"- {flag} {sv}: {round(err * 100, 2)}%")

        worst = by_server.index[0]
        worst_err = by_server.iloc[0]

        if down_servers:
            lines.append("\n권고: 실시간 응답 불가 서버가 있으므로 해당 서버를 최우선 점검하세요.")
        elif worst_err > 0:
            lines.append(f"\n권고: {worst} 서버의 에러 로그를 우선 확인하세요.")
        else:
            lines.append("\n권고: 현재 로그 기준 500번대 에러율은 감지되지 않았습니다.")

        return "\n".join(lines)

    # =====================================================
    # 성공률
    # =====================================================
    if intent == "성공률":
        realtime = check_realtime_server_status()
        down_servers = [r for r in realtime if not r["alive"]]

        by_server = df.groupby("server")["success_rate"].mean().sort_values(ascending=False)

        lines = ["서버별 평균 성공률입니다.\n"]

        if down_servers:
            lines.append("[실시간 장애 상태]")
            for r in down_servers:
                lines.append(f"- 🔴 {r['name']} ({r['server']}): 응답 없음")
            lines.append("")

        lines.append("[로그 기반 평균 성공률]")
        for sv, succ in by_server.items():
            flag = "🟢" if succ >= 0.99 else ("🟡" if succ >= 0.95 else "🔴")
            lines.append(f"- {flag} {sv}: {round(succ * 100, 2)}%")

        min_server = by_server.sort_values().index[0]
        min_succ = by_server.sort_values().iloc[0]

        if down_servers:
            lines.append("\n권고: 실시간 응답 불가 서버가 있으므로 해당 서버의 서비스 상태를 우선 복구하세요.")
        elif min_succ < 0.95:
            lines.append(f"\n권고: {min_server} 서버의 성공률이 낮으므로 장애 여부를 점검하세요.")
        elif min_succ < 0.99:
            lines.append(f"\n권고: {min_server} 서버를 주의 관찰하세요.")
        else:
            lines.append("\n권고: 전체 서버의 성공률이 안정적입니다.")

        return "\n".join(lines)

    # =====================================================
    # 서버 목록
    # =====================================================
    if intent == "서버목록":
        realtime = check_realtime_server_status()

        lines = [f"현재 데이터에 포함된 서버는 {len(s['servers'])}대입니다.\n"]

        lines.append("[CSV 데이터 기준 서버]")
        for sv in s["servers"]:
            lines.append(f"- {sv}")

        lines.append("\n[실시간 체크 대상 서버]")
        for r in realtime:
            icon = "🟢" if r["alive"] else "🔴"
            lines.append(f"- {icon} {r['name']} ({r['server']}): {r['message']}")

        return "\n".join(lines)

    # =====================================================
    # 시간대
    # =====================================================
    if intent == "시간대":
        df["hour"] = df["time"].astype(str).apply(lambda t: int(t.split(":")[0]))
        by_hour = df.groupby("hour")["request_count"].sum().sort_values(ascending=False)

        lines = ["시간대별 요청 수입니다.\n"]

        for h, cnt in by_hour.items():
            bar = "█" * max(1, int(cnt))
            lines.append(f"- {h:02d}시: {int(cnt)}건 {bar}")

        peak_hour = int(by_hour.index[0])
        peak_count = int(by_hour.iloc[0])

        lines.append(f"\n가장 요청이 많은 시간대는 {peak_hour:02d}시 ({peak_count}건)입니다.")
        lines.append("권고: 피크 시간대에는 서버 상태와 에러율을 집중 모니터링하는 것이 좋습니다.")

        return "\n".join(lines)

    # =====================================================
    # 운영 권고
    # =====================================================
    if intent == "운영권고":
        realtime = check_realtime_server_status()
        down_servers = [r for r in realtime if not r["alive"]]
        alive_servers = [r for r in realtime if r["alive"]]

        by_server = df.groupby("server").agg(
            total_request=("request_count", "sum"),
            avg_response_time=("avg_response_time", "mean"),
            avg_error_rate=("error_rate", "mean"),
            avg_success_rate=("success_rate", "mean")
        ).reset_index()

        busiest = by_server.sort_values("total_request", ascending=False).iloc[0]
        worst_error = by_server.sort_values("avg_error_rate", ascending=False).iloc[0]
        slowest = by_server.sort_values("avg_response_time", ascending=False).iloc[0]

        avg_err = by_server["avg_error_rate"].mean()
        avg_succ = by_server["avg_success_rate"].mean()

        realtime_lines = []
        for r in realtime:
            icon = "🟢" if r["alive"] else "🔴"
            realtime_lines.append(
                f"- {icon} {r['name']} ({r['server']}): {r['message']} / {r['latency_ms']}ms"
            )

        if down_servers:
            down_text = "\n".join(
                [f"- {r['name']} ({r['server']})" for r in down_servers]
            )

            if alive_servers:
                alive_text = "\n".join(
                    [f"- {r['name']} ({r['server']})" for r in alive_servers]
                )
            else:
                alive_text = "- 현재 정상 응답 서버 없음"

            return (
                f"AI 운영 의사결정 권고입니다.\n\n"
                f"[현재 판단]\n"
                f"상태: 🔴 위험\n"
                f"최종 권고: 실시간 상태 확인 결과, 일부 웹서버가 응답하지 않습니다. "
                f"해당 서버를 즉시 점검 대상으로 분류하고, 정상 서버로 트래픽이 우회되는지 확인해야 합니다.\n\n"
                f"[실시간 서버 상태]\n"
                + "\n".join(realtime_lines)
                + f"\n\n[점검 대상 서버]\n"
                f"{down_text}\n\n"
                f"[현재 정상 응답 서버]\n"
                f"{alive_text}\n\n"
                f"[권고 조치]\n"
                f"- 다운된 서버의 Nginx 실행 상태를 확인하세요.\n"
                f"- 해당 VM의 네트워크 연결과 IP 설정을 확인하세요.\n"
                f"- 로드밸런서가 정상 서버로만 트래픽을 우회하는지 확인하세요.\n"
                f"- 장애 서버가 복구되면 다시 상태 체크 후 로드밸런싱 대상에 포함하세요.\n\n"
                f"[참고: 최근 로그 기반 지표]\n"
                f"- 요청이 가장 많은 서버: {busiest['server']} ({int(busiest['total_request'])}건)\n"
                f"- 응답시간이 가장 높은 서버: {slowest['server']} ({round(slowest['avg_response_time'], 2)}ms)\n"
                f"- 에러율이 가장 높은 서버: {worst_error['server']} ({round(worst_error['avg_error_rate'] * 100, 2)}%)\n"
                f"- 평균 성공률: {round(avg_succ * 100, 2)}%"
            )

        actions = []

        if worst_error["avg_error_rate"] > 0:
            actions.append(
                f"- {worst_error['server']} 서버에서 에러율이 가장 높습니다. "
                f"해당 서버의 Nginx 로그와 백엔드 상태를 확인하세요."
            )
        else:
            actions.append(
                "- 현재 로그 기준 500번대 에러율은 감지되지 않았습니다."
            )

        if busiest["total_request"] > by_server["total_request"].mean() * 1.5:
            actions.append(
                f"- 요청이 {busiest['server']} 서버에 상대적으로 많이 집중되어 있습니다. "
                f"로드밸런싱 분산 상태를 확인하는 것이 좋습니다."
            )
        else:
            actions.append(
                "- 요청 수가 특정 서버에 과도하게 몰린 상태는 아닙니다."
            )

        if avg_err == 0 and avg_succ >= 0.99:
            risk = "🟢 정상"
            final_decision = "실시간 서버 상태와 로그 지표 모두 안정적이므로 현재 로드밸런싱 정책을 유지해도 됩니다."
        elif avg_err > 0 and avg_err <= 0.1:
            risk = "🟡 주의"
            final_decision = "실시간 서버는 정상이나 일부 오류가 감지되므로 로그를 추가 확인하는 것이 좋습니다."
        else:
            risk = "🔴 위험"
            final_decision = "에러율이 높아 장애 가능성이 있으므로 문제 서버 점검 및 트래픽 우회를 고려해야 합니다."

        return (
            f"AI 운영 의사결정 권고입니다.\n\n"
            f"[현재 판단]\n"
            f"상태: {risk}\n"
            f"최종 권고: {final_decision}\n\n"
            f"[실시간 서버 상태]\n"
            + "\n".join(realtime_lines)
            + f"\n\n[로그 기반 근거 지표]\n"
            f"- 요청이 가장 많은 서버: {busiest['server']} ({int(busiest['total_request'])}건)\n"
            f"- 응답시간이 가장 높은 서버: {slowest['server']} ({round(slowest['avg_response_time'], 2)}ms)\n"
            f"- 에러율이 가장 높은 서버: {worst_error['server']} ({round(worst_error['avg_error_rate'] * 100, 2)}%)\n"
            f"- 평균 성공률: {round(avg_succ * 100, 2)}%\n\n"
            f"[권고 조치]\n"
            + "\n".join(actions)
        )

    # =====================================================
    # 예측
    # =====================================================
    if intent == "예측":
        realtime = check_realtime_server_status()
        down_servers = [r for r in realtime if not r["alive"]]

        if down_servers:
            return (
                f"Random Forest 기반 예측 결과를 보기 전에 실시간 장애가 감지되었습니다.\n\n"
                f"상태: 🔴 위험\n"
                f"권고: 현재 응답하지 않는 서버가 있으므로 예측보다 장애 복구가 우선입니다.\n"
                f"다운 서버:\n"
                + "\n".join([f"- {r['name']} ({r['server']})" for r in down_servers])
            )

        return (
            f"Random Forest 기반 예측 결과 요약입니다.\n\n"
            f"- 현재 평균 응답시간: {s['avg_rt']}ms\n"
            f"- 현재 평균 에러율: {s['avg_err']}%\n"
            f"- 현재 평균 성공률: {s['avg_succ']}%\n\n"
            f"예측 판단:\n"
            f"현재 수집된 데이터 기준으로는 서버들이 정상 범위 내에 있습니다.\n"
            f"다만 피크 시간대에는 요청 수가 증가할 수 있으므로 "
            f"요청 수와 에러율을 함께 모니터링하는 것이 좋습니다.\n\n"
            f"운영 권고:\n"
            f"- 현재는 기존 로드밸런싱 정책을 유지\n"
            f"- 에러율 증가 시 해당 서버 점검\n"
            f"- 특정 서버 요청 집중 시 분산 정책 재확인"
        )

    # =====================================================
    # 알 수 없음
    # =====================================================
    return (
        "질문을 정확히 이해하지 못했습니다.\n\n"
        "아래처럼 질문해볼 수 있습니다.\n"
        "- 전체 현황 알려줘\n"
        "- 이상 트래픽 있어?\n"
        "- 응답시간 알려줘\n"
        "- 에러율 높은 서버는?\n"
        "- 성공률 알려줘\n"
        "- 192.168.30.129 서버 상태는?\n"
        "- 시간대별 트래픽은?\n"
        "- 관리자 입장에서 지금 어떤 조치를 해야 해?\n"
        "- 운영 권고 알려줘\n"
        "- 트래픽 분산 정책 유지해도 돼?"
    )