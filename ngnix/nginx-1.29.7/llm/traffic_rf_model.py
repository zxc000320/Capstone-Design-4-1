"""
서버 접속 트래픽 분석 및 예측 시스템
  - 전처리  : preprocess_nginx.py 를 import 해서 실행 (별도 파일 유지)
  - 학습    : 멀티 타겟 Random Forest
  - 저장    : rf_models.pkl 에 모델 저장
  - 재사용  : 로그 변경 없으면 저장된 모델 재사용, 변경 시 자동 재학습

[회귀 모델 4종]
  1. request_count     : 요청 수 예측 (트래픽)
  2. avg_response_time : 평균 응답시간 예측
  3. error_rate        : 에러율 예측
  4. success_rate      : 성공률 예측

[분류 모델 1종]
  5. is_anomaly        : 이상 트래픽 탐지
"""

import hashlib
import importlib
import os
import pickle
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.metrics import (
    classification_report,
    mean_absolute_error,
    mean_squared_error,
    r2_score,
    roc_auc_score,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────
# 경로 설정
# ─────────────────────────────────────────────────────────────

BASE_DIR   = r"C:\Users\cemin\OneDrive\바탕 화면\ngnix\nginx-1.29.7\logs"
CSV_PATH   = os.path.join(BASE_DIR, "processed_data.csv")
MODEL_PATH = os.path.join(BASE_DIR, "rf_models.pkl")  # 학습된 모델 저장 파일
HASH_PATH  = os.path.join(BASE_DIR, "log_hash.txt")   # 로그 변경 감지용 해시

# preprocess_nginx.py 가 참조하는 로그 파일 경로 (해시 감지용)
LOG_PATHS  = [
    os.path.join(BASE_DIR, "lb_access.log"),
    os.path.join(BASE_DIR, "access.log"),
]

# ─────────────────────────────────────────────────────────────
# 1. preprocess_nginx.py import 및 실행
# ─────────────────────────────────────────────────────────────

# 같은 폴더(BASE_DIR)를 파이썬 경로에 추가해서 import 가능하게 함
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def run_preprocess() -> pd.DataFrame:
    """
    preprocess_nginx.py 를 실행해 전처리 CSV 를 갱신한 뒤 DataFrame 으로 반환.
    preprocess_nginx.py 를 직접 수정해도 여기서 자동 반영됨.
    """
    try:
        import preprocess_nginx
        # 이미 import 된 경우에도 최신 상태로 재실행
        importlib.reload(preprocess_nginx)
    except ModuleNotFoundError:
        raise ModuleNotFoundError(
            f"preprocess_nginx.py 를 찾을 수 없습니다.\n"
            f"확인 경로: {BASE_DIR}"
        )

    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(
            f"전처리 후 CSV 가 없습니다: {CSV_PATH}\n"
            f"preprocess_nginx.py 가 정상 실행됐는지 확인하세요."
        )

    df = pd.read_csv(CSV_PATH)
    print(f"✅ 전처리 완료 ({len(df)}행) → {CSV_PATH}")
    return df


# ─────────────────────────────────────────────────────────────
# 2. 로그 변경 감지
# ─────────────────────────────────────────────────────────────

def get_log_hash() -> str:
    """로그 파일(또는 CSV)의 MD5 해시 반환"""
    for path in LOG_PATHS:
        if os.path.exists(path):
            with open(path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
    if os.path.exists(CSV_PATH):
        with open(CSV_PATH, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    return ""

def is_log_changed() -> bool:
    current = get_log_hash()
    if not os.path.exists(HASH_PATH):
        return True
    with open(HASH_PATH, "r") as f:
        return f.read().strip() != current

def save_log_hash():
    with open(HASH_PATH, "w") as f:
        f.write(get_log_hash())


# ─────────────────────────────────────────────────────────────
# 3. 피처 엔지니어링
# ─────────────────────────────────────────────────────────────

REGRESSION_TARGETS = {
    "request_count":     "요청 수 (트래픽)",
    "avg_response_time": "평균 응답시간 (ms)",
    "error_rate":        "에러율",
    "success_rate":      "성공률",
}
CLF_TARGET = "is_anomaly"

BASE_FEATURES = [
    "hour", "minute", "is_peak",
    "server_encoded", "subnet_encoded",
    "response_range",
]
FEATURES_REG = {
    "request_count":     BASE_FEATURES + ["avg_response_time", "error_rate",
                                           "max_response_time", "min_response_time",
                                           "success_rate"],
    "avg_response_time": BASE_FEATURES + ["request_count", "error_rate",
                                           "max_response_time", "min_response_time",
                                           "success_rate"],
    "error_rate":        BASE_FEATURES + ["request_count", "avg_response_time",
                                           "max_response_time", "min_response_time",
                                           "success_rate"],
    "success_rate":      BASE_FEATURES + ["request_count", "avg_response_time",
                                           "error_rate",
                                           "max_response_time", "min_response_time"],
}
FEATURES_CLF = BASE_FEATURES + ["request_count", "avg_response_time", "error_rate",
                                  "max_response_time", "min_response_time", "success_rate"]


def feature_engineering(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["server"]         = df["server"].replace("-", "unknown")
    df["hour"]           = df["time"].apply(lambda t: int(t.split(":")[0]))
    df["minute"]         = df["time"].apply(lambda t: int(t.split(":")[1]))
    df["is_peak"]        = df["hour"].between(9, 18).astype(int)
    df["server_subnet"]  = df["server"].apply(
        lambda s: ".".join(s.split(".")[:3]) if s != "unknown" else "unknown"
    )
    df["response_range"] = df["max_response_time"] - df["min_response_time"]
    thr = df["avg_response_time"].mean() + 2 * df["avg_response_time"].std()
    df["is_anomaly"]     = (
        (df["error_rate"] > 0) | (df["avg_response_time"] > thr)
    ).astype(int)
    return df


def encode_categoricals(df, le_server=None, le_subnet=None):
    df = df.copy()
    if le_server is None:
        le_server = LabelEncoder()
        df["server_encoded"] = le_server.fit_transform(df["server"])
    else:
        df["server_encoded"] = df["server"].apply(
            lambda v: le_server.transform([v])[0]
            if v in le_server.classes_ else le_server.transform(["unknown"])[0]
        )
    if le_subnet is None:
        le_subnet = LabelEncoder()
        df["subnet_encoded"] = le_subnet.fit_transform(df["server_subnet"])
    else:
        df["subnet_encoded"] = df["server_subnet"].apply(
            lambda v: le_subnet.transform([v])[0]
            if v in le_subnet.classes_ else le_subnet.transform(["unknown"])[0]
        )
    return df, le_server, le_subnet


# ─────────────────────────────────────────────────────────────
# 4. 데이터 보강 (실 데이터 부족 시)
# ─────────────────────────────────────────────────────────────

def augment_data(df: pd.DataFrame, n_samples: int = 600, seed: int = 42) -> pd.DataFrame:
    """
    실제 데이터가 적을 때 통계 분포 기반으로 학습용 샘플을 추가 생성합니다.
    운영 데이터가 충분히 쌓이면 이 함수 호출을 제거해도 됩니다.
    """
    rng         = np.random.default_rng(seed)
    hours       = rng.integers(0, 24, n_samples)
    minutes     = rng.integers(0, 60, n_samples)
    servers     = rng.choice(df["server"].unique(), n_samples)
    subnets     = [".".join(s.split(".")[:3]) if s != "unknown" else "unknown"
                   for s in servers]
    base_req    = np.where((hours >= 9) & (hours <= 18), 5, 2)
    req_count   = rng.poisson(base_req).clip(1, 50).astype(int)
    anomaly     = rng.random(n_samples) < 0.10
    avg_rt      = np.where(anomaly, rng.uniform(5, 20, n_samples),
                           rng.uniform(0.5, 2.0, n_samples))
    error_rate  = np.where(anomaly, rng.uniform(0.1, 1.0, n_samples), 0.0)
    success_rate= (1.0 - error_rate).clip(0, 1)
    max_rt      = (avg_rt * rng.uniform(1.0, 3.0, n_samples)).astype(int).clip(1)
    min_rt      = np.ones(n_samples, dtype=int)

    return pd.DataFrame({
        "time":              [f"{h:02d}:{m:02d}" for h, m in zip(hours, minutes)],
        "server":            servers,
        "request_count":     req_count,
        "avg_response_time": np.round(avg_rt, 2),
        "error_rate":        np.round(error_rate, 4),
        "max_response_time": max_rt,
        "min_response_time": min_rt,
        "success_rate":      np.round(success_rate, 4),
        "hour":              hours,
        "minute":            minutes,
        "is_peak":           ((hours >= 9) & (hours <= 18)).astype(int),
        "server_subnet":     subnets,
        "response_range":    max_rt - min_rt,
        "is_anomaly":        anomaly.astype(int),
    })


# ─────────────────────────────────────────────────────────────
# 5. 모델 저장 / 불러오기
# ─────────────────────────────────────────────────────────────

def save_models(models_reg, model_clf, le_server, le_subnet):
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({
            "models_reg": models_reg,
            "model_clf":  model_clf,
            "le_server":  le_server,
            "le_subnet":  le_subnet,
        }, f)
    print(f"💾 모델 저장 완료 → {MODEL_PATH}")

def load_models():
    with open(MODEL_PATH, "rb") as f:
        b = pickle.load(f)
    print(f"📂 저장된 모델 불러오기 완료 → {MODEL_PATH}")
    return b["models_reg"], b["model_clf"], b["le_server"], b["le_subnet"]


# ─────────────────────────────────────────────────────────────
# 6. 학습
# ─────────────────────────────────────────────────────────────

RF_PARAMS = dict(n_estimators=200, max_depth=10, min_samples_split=4,
                 min_samples_leaf=2, max_features="sqrt", random_state=42, n_jobs=-1)

def train_all(df_all: pd.DataFrame):
    df_all, le_server, le_subnet = encode_categoricals(df_all)
    y_c = df_all[CLF_TARGET]
    print(f"  이상 트래픽 비율: {y_c.mean()*100:.1f}% ({y_c.sum()} / {len(y_c)}건)")

    # 회귀 4종
    models_reg = {}
    print("\n  [회귀 모델 학습]")
    for target, label in REGRESSION_TARGETS.items():
        X = df_all[FEATURES_REG[target]]
        y = df_all[target]
        X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42)
        model = RandomForestRegressor(**RF_PARAMS)
        model.fit(X_tr, y_tr)
        models_reg[target] = model
        pred = model.predict(X_te)
        cv   = cross_val_score(model, X, y, cv=5, scoring="r2")
        print(f"    {label:<20}  R²={r2_score(y_te, pred):.4f}  "
              f"MAE={mean_absolute_error(y_te, pred):.4f}  "
              f"CV R²={cv.mean():.4f}±{cv.std():.4f}")

    # 분류
    print("\n  [분류 모델 학습 - 이상 탐지]")
    X_clf = df_all[FEATURES_CLF]
    X_tr, X_te, yc_tr, yc_te = train_test_split(
        X_clf, y_c, test_size=0.2, random_state=42, stratify=y_c
    )
    model_clf = RandomForestClassifier(**RF_PARAMS, class_weight="balanced")
    model_clf.fit(X_tr, yc_tr)
    pred_c  = model_clf.predict(X_te)
    proba_c = model_clf.predict_proba(X_te)[:, 1]
    print(classification_report(yc_te, pred_c, target_names=["정상", "이상"], zero_division=0))
    if len(np.unique(yc_te)) > 1:
        print(f"    ROC-AUC : {roc_auc_score(yc_te, proba_c):.4f}")
    cv_c = cross_val_score(model_clf, X_clf, y_c, cv=5, scoring="roc_auc")
    print(f"    CV ROC-AUC (5-fold): {cv_c.mean():.4f} ± {cv_c.std():.4f}")

    return models_reg, model_clf, le_server, le_subnet


# ─────────────────────────────────────────────────────────────
# 7. 실시간 단일 예측
# ─────────────────────────────────────────────────────────────

def predict_all(models_reg, model_clf, le_server, le_subnet, record: dict) -> dict:
    """
    단일 레코드 예측 (4종 회귀 + 이상 분류)

    record 필수 키:
        hour, minute, server,
        request_count, avg_response_time, error_rate,
        max_response_time, min_response_time, success_rate
    """
    r = record.copy()
    r["is_peak"]        = 1 if 9 <= r["hour"] <= 18 else 0
    r["response_range"] = r["max_response_time"] - r["min_response_time"]
    r["server_subnet"]  = ".".join(r["server"].split(".")[:3]) \
                          if r["server"] != "unknown" else "unknown"
    r["server_encoded"] = (le_server.transform([r["server"]])[0]
                           if r["server"] in le_server.classes_
                           else le_server.transform(["unknown"])[0])
    r["subnet_encoded"] = (le_subnet.transform([r["server_subnet"]])[0]
                           if r["server_subnet"] in le_subnet.classes_
                           else le_subnet.transform(["unknown"])[0])

    results = {}
    for target in REGRESSION_TARGETS:
        X = pd.DataFrame([r])[FEATURES_REG[target]]
        results[target] = max(0.0, round(float(models_reg[target].predict(X)[0]), 4))

    X_clf = pd.DataFrame([r])[FEATURES_CLF]
    prob  = float(model_clf.predict_proba(X_clf)[0, 1])
    results["anomaly_probability"] = round(prob, 4)
    results["is_anomaly"]          = bool(model_clf.predict(X_clf)[0])
    results["risk_level"]          = (
        "🔴 위험" if prob > 0.7 else "🟡 주의" if prob > 0.3 else "🟢 정상"
    )
    return results


# ─────────────────────────────────────────────────────────────
# 8. 전체 데이터 예측 결과 출력
# ─────────────────────────────────────────────────────────────

def print_predictions(df_raw, models_reg, model_clf, le_server, le_subnet):
    df = feature_engineering(df_raw)
    df, _, _ = encode_categoricals(df, le_server, le_subnet)

    rows = []
    for _, row in df.iterrows():
        p = predict_all(models_reg, model_clf, le_server, le_subnet, row.to_dict())
        rows.append({
            "시간":         row["time"],
            "서버":         row["server"],
            "실제_요청수":   int(row["request_count"]),
            "예측_요청수":   round(p["request_count"], 1),
            "실제_응답시간": round(row["avg_response_time"], 2),
            "예측_응답시간": round(p["avg_response_time"], 2),
            "실제_에러율":   round(row["error_rate"], 4),
            "예측_에러율":   round(p["error_rate"], 4),
            "실제_성공률":   round(row["success_rate"], 4),
            "예측_성공률":   round(p["success_rate"], 4),
            "이상확률":      f"{p['anomaly_probability']*100:.1f}%",
            "위험등급":      p["risk_level"],
        })

    pd.set_option("display.width", 200)
    pd.set_option("display.max_rows", 100)
    print(pd.DataFrame(rows).to_string(index=False))


# ─────────────────────────────────────────────────────────────
# 9. 메인
# ─────────────────────────────────────────────────────────────

def main():
    SEP = "=" * 65
    print(SEP)
    print("  서버 트래픽 분석 및 예측 시스템")
    print(SEP)

    # ── Step 1: preprocess_nginx.py 실행해서 전처리
    print("\n[Step 1] nginx 로그 전처리 (preprocess_nginx.py)")
    df_raw = run_preprocess()

    # ── Step 2: 로그 변경 여부 확인 후 학습 or 재사용
    log_changed = is_log_changed()

    if os.path.exists(MODEL_PATH) and not log_changed:
        print("\n[Step 2] 로그 변경 없음 → 저장된 모델 재사용")
        models_reg, model_clf, le_server, le_subnet = load_models()
    else:
        reason = "첫 실행" if not os.path.exists(MODEL_PATH) else "로그 변경 감지"
        print(f"\n[Step 2] {reason} → 모델 재학습")

        df_fe    = feature_engineering(df_raw)
        df_synth = augment_data(df_fe, n_samples=600)
        df_all   = pd.concat([df_fe, df_synth], ignore_index=True)
        print(f"  학습 데이터: {len(df_all)}행 (실제 {len(df_fe)} + 시뮬레이션 {len(df_synth)})")

        models_reg, model_clf, le_server, le_subnet = train_all(df_all)
        save_models(models_reg, model_clf, le_server, le_subnet)
        save_log_hash()

    # ── Step 3: 전체 예측 결과 출력
    print(f"\n{SEP}")
    print("  [예측 결과] 실제 수집 데이터")
    print(SEP)
    print_predictions(df_raw, models_reg, model_clf, le_server, le_subnet)

    # ── Step 4: 단일 예측 데모
    print(f"\n{SEP}")
    print("  [단일 예측 데모]")
    print(SEP)

    test_cases = [
        {"label": "정상 케이스",
         "hour": 16, "minute": 34, "server": "192.168.30.129:80",
         "request_count": 3, "avg_response_time": 1.0, "error_rate": 0.0,
         "max_response_time": 1, "min_response_time": 1, "success_rate": 1.0},
        {"label": "이상 케이스 (새벽 고에러)",
         "hour": 3, "minute": 15, "server": "192.168.37.133:80",
         "request_count": 1, "avg_response_time": 12.5, "error_rate": 0.8,
         "max_response_time": 30, "min_response_time": 1, "success_rate": 0.2},
        {"label": "주의 케이스 (응답시간 증가)",
         "hour": 14, "minute": 5, "server": "192.168.30.130:80",
         "request_count": 5, "avg_response_time": 4.2, "error_rate": 0.05,
         "max_response_time": 10, "min_response_time": 1, "success_rate": 0.95},
    ]

    for i, case in enumerate(test_cases, 1):
        label = case.pop("label")
        r = predict_all(models_reg, model_clf, le_server, le_subnet, case)
        print(f"\n  케이스 {i} │ {label}")
        print(f"    서버 / 시간    : {case['server']} @ {case['hour']:02d}:{case['minute']:02d}")
        print(f"    예측 요청 수   : {r['request_count']:.1f} 건")
        print(f"    예측 응답시간  : {r['avg_response_time']:.2f} ms")
        print(f"    예측 에러율    : {r['error_rate']*100:.2f}%")
        print(f"    예측 성공률    : {r['success_rate']*100:.2f}%")
        print(f"    이상 확률      : {r['anomaly_probability']*100:.1f}%")
        print(f"    위험 등급      : {r['risk_level']}")

    print(f"\n✅ 완료")


if __name__ == "__main__":
    main()
