# AI 기반 L4 로드밸런싱 트래픽 최적화 및 운영 의사결정 지원 시스템

배재대학교 정보보안학과 캡스톤디자인 2조

nginx 로드밸런서 뒤에 웹 서버 2대(VMware VM)를 두고, LB 접속 로그를 전처리해 Random Forest로 트래픽을 분석·예측합니다.
결과는 관리자 대시보드(Flask)와 TF-IDF 기반 자연어 챗봇으로 조회합니다. 챗봇은 LLM 없이 동작합니다.

```
사용자 → nginx LB(:80 → :443) → Web1 / Web2 (VM)
                │
                └─ lb_access.log → 전처리 → processed_data.csv → RF 모델 / NLP 엔진
                                                                  │
관리자 ← Flask 대시보드(:5000) · AI 챗봇(/chat) ←─────────────────┘
```

## 폴더 구조

```
ngnix/
├── admin_page/
│   ├── app.py                     # Flask 관리자 대시보드 + 챗봇 API
│   └── logs/                      # 관리자 보안 로그, 날짜별 관제 CSV (실행 시 자동 생성)
└── nginx-1.29.7/
    ├── nginx.exe
    ├── conf/nginx.conf            # 로드밸런싱 설정 (upstream, SSL)
    ├── certs/                     # lb.crt, lb.key (자체서명 인증서)
    ├── logs/
    │   ├── lb_access.log          # LB 접속 로그 (분석 원본)
    │   ├── preprocess_nginx.py    # 로그 → processed_data.csv 전처리
    │   ├── processed_data.csv     # 전처리 결과 (시간대·서버별 집계)
    │   └── rf_models.pkl          # 학습된 RF 모델
    └── llm/
        ├── traffic_rf_model.py    # 전처리 실행 + RF 학습/예측
        ├── nlp_engine.py          # TF-IDF 의도 분류 + 응답 생성
        └── chat.html              # 챗봇 화면
```

## 실행 환경

- Windows (nginx.exe 사용)
- Python 3.11 이상
- VMware에서 웹 서버 VM 2대 구동 (각각 80번 포트로 웹 서비스)

```
pip install flask requests pandas numpy scikit-learn
```

## 설치 전 꼭 확인할 것

### 1. 폴더는 `C:\` 바로 아래에 둘 것

모든 경로가 하드코딩되어 있습니다. 저장소의 `ngnix` 폴더를 그대로 `C:\ngnix`에 놓아야 합니다.

일부 파일에는 개발자 PC 경로(`C:\Users\cemin\OneDrive\바탕 화면\ngnix\...`)가 남아 있으니 `C:\ngnix\...`로 바꿔 주세요.

| 파일 | 수정할 항목 |
|---|---|
| `nginx-1.29.7/conf/nginx.conf` | `ssl_certificate`, `ssl_certificate_key` 경로 |
| `nginx-1.29.7/llm/traffic_rf_model.py` | `BASE_DIR` → `C:\ngnix\nginx-1.29.7\logs` |

### 2. 웹 서버 IP를 내 환경에 맞게 바꿀 것

`192.168.37.133`, `192.168.37.134`는 VMware에서 구동 중인 웹 서버 VM의 IP입니다.
VMware는 메인 PC마다 다른 대역을 할당하므로, 설치 환경에서 VM IP를 확인한 뒤 아래 파일을 모두 같은 값으로 수정해야 합니다.

| 파일 | 수정할 항목 |
|---|---|
| `nginx-1.29.7/conf/nginx.conf` | `upstream backend_servers` 안의 `server` 두 줄 |
| `admin_page/app.py` | `MONITOR_TARGETS` (Web1, Web2) |
| `nginx-1.29.7/llm/nlp_engine.py` | `REALTIME_TARGETS` (Web1, Web2) |

### 3. 이전 PC의 로그가 섞이지 않게 할 것

`lb_access.log`를 다른 PC에서 그대로 복사해 오면, 이전 PC의 VM IP가 로그에 남아 있어 분석 결과에 서버가 2대보다 많이 나타날 수 있습니다.
새 환경에서는 `lb_access.log`를 비우거나 현재 IP 항목만 남긴 뒤 시작하세요.

## 실행 순서

1. 웹 서버 VM 2대를 켭니다.
2. nginx를 실행합니다.
   ```
   cd C:\ngnix\nginx-1.29.7
   start nginx
   ```
   중지는 `nginx -s stop`, 설정 반영은 `nginx -s reload`입니다.
3. 브라우저로 LB에 몇 번 접속해 `logs\lb_access.log`에 기록이 쌓이는지 확인합니다.
4. 전처리와 모델 학습을 실행합니다.
   ```
   cd C:\ngnix\nginx-1.29.7\llm
   python traffic_rf_model.py
   ```
   `preprocess_nginx.py`가 자동으로 실행되어 `processed_data.csv`를 갱신합니다.
   로그가 바뀌었을 때만 모델을 다시 학습하고, 아니면 저장된 `rf_models.pkl`을 재사용합니다.
5. 관리자 페이지를 실행합니다. 작업 디렉터리를 `admin_page`로 맞춰야 로그 폴더가 올바른 위치에 생깁니다.
   ```
   cd C:\ngnix\admin_page
   python app.py
   ```
6. `http://127.0.0.1:5000`에 접속해 로그인합니다.

## 주요 기능

- **관제 대시보드** (`/`): 웹 서버 상태와 응답시간을 5초마다 갱신하고, 최근 관리자 보안 로그와 LB 접속 로그를 보여줍니다. 상태 체크 결과는 날짜별 CSV로 자동 저장됩니다.
- **로그인 보호**: 비밀번호 해시 검증, CSRF 토큰, 5회 실패 시 10분 잠금, 세션 30분 만료, 보안 헤더(CSP 등)를 적용했습니다.
- **트래픽 분석 AI** (`/chat`): 자연어 질문을 TF-IDF(문자 2~3-gram)와 코사인 유사도로 의도 분류해 답합니다.
  지원 의도는 전체현황, 이상탐지, 응답시간, 트래픽, 에러율, 성공률, 서버목록, 시간대, 운영권고, 예측입니다.
  - 예: "지금 서버 상태 어때?", "이상 트래픽 있어?", "피크 시간대 알려줘"

## API

| 경로 | 메서드 | 설명 |
|---|---|---|
| `/api/traffic-data` | GET | `processed_data.csv` 기반 요약과 시간대·서버별 위험도 |
| `/api/chat` | POST | `{"message": "..."}`를 보내면 `{"reply", "intent"}` 반환 |

두 API 모두 로그인 세션이 필요합니다.

## 팀

- 지도교수: 강아름 교수님
- 팀장: 김진웅
- 팀원: 김재민, 최동명, 이유준
