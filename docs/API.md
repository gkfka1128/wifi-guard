# 와이파이 지킴이 백엔드 API (v1)

프론트엔드가 백엔드에 붙을 때 필요한 것은 이 문서와 `frontend/wifiguard-client.js` 두 가지다.
`frontend/` 의 임시 대시보드(`index.html`, `app.js`, `style.css`)는 이 클라이언트를 쓰는 예시다.

## 규격 파일과 변경 규칙

| 파일 | 내용 |
|---|---|
| `docs/openapi.json` | 기계가 읽는 규격 (OpenAPI 3.0). https://editor.swagger.io 에 붙여 넣으면 화면으로 볼 수 있다 |
| `docs/examples/*.json` | 데모 pcap을 실제로 재생해서 받은 응답. 백엔드 없이 화면을 만들 때 가짜 데이터로 쓴다 |
| 이 문서 | 사람이 읽는 설명 (보안, 판정 단계, 화면에서 지킬 것) |

- 규격 버전은 `/api/meta` 의 `version` (지금 `"1"`).
- **필드 추가**는 버전을 그대로 둔다. 프론트는 모르는 필드를 무시해야 한다.
- **필드 이름·타입 변경, 삭제, 상태 코드 변경**은 버전을 올리고 카톡방에 먼저 알린다.
- `tests/test_server.py` 의 `ContractTest` 가 실제 응답을 `openapi.json` 과 비교한다.
  응답을 바꾸고 규격을 안 고치면 테스트가 깨진다.
- 예시를 다시 만들 때: `.venv\Scripts\python docs\make_examples.py` (데모를 재생해 `docs/examples/` 갱신). 규격을 바꿀 때는 `openapi.json` 을 직접 고치고 테스트를 돌린다.

## 붙이는 방법 두 가지

**1. 백엔드가 프론트 파일을 같이 내보내기 (권장)**
만든 파일을 `frontend/` 에 넣거나 `--frontend 폴더` 로 지정한다. 같은 주소(127.0.0.1:5000)에서 열리므로
CORS 설정이 필요 없고, 클라이언트는 `base: ""` 로 쓴다.

```powershell
.venv\Scripts\python run_server.py --no-capture --demo --frontend ..\우리-프론트\dist
```

**2. 프론트 개발 서버(Vite·React·Live Server)를 따로 띄우기**
`http://localhost` 와 `http://127.0.0.1` 의 3000·5173·5500·8080 포트는 기본으로 허용한다.
그 밖의 주소는 `--allow-origin http://localhost:4200` 처럼 추가한다. 클라이언트는 `base: "http://127.0.0.1:5000"`.
목록에 없는 출처에서 온 요청에는 CORS 헤더를 주지 않고, 소켓 연결도 받지 않는다.

서버는 `127.0.0.1` 에서만 열린다. 같은 와이파이의 다른 사람은 접속할 수 없다.

## 클라이언트 (`wifiguard-client.js`)

```html
<script src="http://127.0.0.1:5000/vendor/socket.io.min.js"></script>  <!-- 백엔드가 준다. CDN 주소도 된다 -->
<script src="wifiguard-client.js"></script>
<script>
  const guard = WifiGuard.connect({
    base: "",
    onStatus: (status) => {},      // 상태가 바뀔 때마다
    onEvents: (list) => {},        // 처음 한 번: 최근 이벤트 100개 (최신순)
    onEvent:  (event) => {},       // 그 뒤 새 이벤트가 하나씩
    onLink:   (state) => {},       // "socket" | "polling" | "offline"
  });
  guard.scan(); guard.learn(); guard.demo(); guard.events({ module: "arp", limit: 20 });
</script>
```

- Socket.IO 스크립트를 못 불러오면(인터넷 없는 실험망) 자동으로 3초 폴링으로 바꾼다.
- 소켓이 끊겼다 다시 붙으면, 그 사이 놓친 이벤트를 `since` 로 채워서 `onEvent` 로 준다.
- `WifiGuard.LEVEL_KO`, `WifiGuard.RANK` 로 단계 이름과 순서를 쓸 수 있다.
- **서버가 보내는 문자열은 화면에 `textContent` 로만 넣는다.** SSID는 주변 AP가 마음대로 정할 수 있어서,
  `innerHTML` 로 넣으면 AP 이름에 넣은 스크립트가 대시보드에서 실행될 수 있다.

## 판정 단계

| level | 한글 | 뜻 |
|---|---|---|
| `normal` | 정상 | 수집이 되고 있고 이상 신호 없음 |
| `unknown` | 확인 불가 | 수집 실패(Npcap 없음, 권한, AP 목록 못 읽음). **정상이 아니다** |
| `caution` | 주의 | 근거 일부 (ARP 40점, AP 30점, DNS 40점 이상) |
| `warning` | 경고 | 공격으로 볼 근거가 충분 (ARP 60점, AP 50점, DNS 60점 이상) |

화면 색은 정상 = 초록, 확인 불가 = 회색, 주의 = 주황, 경고 = 빨강을 권장한다.
`/api/meta` 의 `levels` 는 낮은 단계에서 높은 단계 순서다.

## 이벤트 형식

REST `/api/events` 의 원소와 Socket.IO `event` 가 모두 이 모양이다.

```json
{
  "id": 5,
  "module": "arp",
  "level": "warning",
  "title": "인터넷 해킹 의심",
  "reason": "공유기 192.168.0.1의 MAC이 00:26:66:4d:ca:18 → 88:36:6c:6a:c0:4c로 바뀜 / …",
  "evidence": { "target_mac": "88:36:6c:6a:c0:4c", "suspect": "88:36:6c:6a:c0:4c", "score": 80,
                "claimed_ips": ["192.168.0.1"], "real_macs": {"192.168.0.1": "00:26:66:4d:ca:18"},
                "frames": [19, 22] },
  "advice": ["netsh wlan disconnect"],
  "timestamp": "2026-10-26T16:34:18+09:00"
}
```

`advice` 는 상황에 따라 달라진다. ARP 경고에서 공유기 MAC을 `learn` 으로 저장해 둔 경우에만
정적 ARP 등록 명령이 더해지고, 저장한 값이 없으면 연결 끊기만 나온다 (처음 본 MAC을 고정하면 공격자 MAC을 고정할 수 있어서).

| 필드 | 설명 |
|---|---|
| `module` | `arp` · `ap` · `dns` · `system` (system은 모듈이 '확인 불가'로 바뀐 기록) |
| `title` | 한 줄 제목 |
| `reason` | 사용자에게 보여 줄 설명 (판단 이유를 ` / ` 로 이어 붙임) |
| `evidence` | 판단 근거. 모듈마다 키가 다르다 (아래) |
| `advice` | 권장 대응 명령. **백엔드는 실행하지 않는다.** 화면에서 보여 주고 복사만 하게 한다 |
| `timestamp` | ISO 8601. pcap 재생이면 패킷이 찍힌 시각 |

`evidence` 키

| module | 키 |
|---|---|
| arp | `target_mac` 의심 MAC, `suspect` 공격자 추정(모르면 "확인 필요"), `score`, `claimed_ips`, `real_macs` {IP: 원래 MAC}, `frames` [처음, 마지막 프레임 번호] |
| ap | `ssid`, `bssid`, `auth`, `signal` (%), `score` |
| dns | `qname`, `client`, `server`, `answers`, `score`, `rules` (D1·D2·D3) |
| system | `module` |

## REST API

모든 응답은 JSON(UTF-8). 실패하면 `{"ok": false, "reason": "…"}`.

**POST는 `X-WifiGuard: 1` 헤더가 꼭 있어야 한다** (없으면 403). `wifiguard-client.js` 가 붙여 준다.
직접 `fetch` 하면 `fetch(url, {method: "POST", headers: {"X-WifiGuard": "1"}})` 처럼 쓴다.
이유: CORS는 다른 사이트가 응답을 읽는 것만 막고 단순 POST가 서버에 닿는 것은 못 막는다. 이 헤더가 있으면
브라우저가 먼저 사전 확인(preflight)을 하고, 허용 목록에 없는 사이트는 거기서 막힌다. 그 밖에
POST의 `Origin` 이 허용 목록에 없으면 403, 주소창 Host가 127.0.0.1/localhost가 아니면 403 (DNS 리바인딩 방지).

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/health` | `{"ok": true, "version": "1"}` |
| GET | `/api/meta` | `levels`, `level_ko`, `modules`(한글 이름), `event_fields`, `demo`(데모 버튼을 보여 줄지) |
| GET | `/api/status` | 전체 상태 (아래) |
| GET | `/api/events` | 이벤트 목록, **최신순**. `limit`(기본 50, 최대 500), `module`, `level`, `since`(이 id보다 새 것만) |
| GET | `/api/trust` | 저장한 기준값 `[{"ssid", "bssids": [...], "gateway_ip", "gateway_mac"}]` |
| GET | `/api/diagnostics` | 실행 환경 점검 `{"npcap": {"label", "ok": true/false/null, "detail"}, "admin", "wlan", "location", "networks"}` (순서 유지). netsh를 부르므로 1–2초 걸린다 |
| POST | `/api/scan` | 주변 AP를 지금 스캔. `{"alerts": 새로 판단한 의심 수, "status": {…}}` |
| POST | `/api/learn` | 지금 연결된 와이파이를 기준값으로 저장. 성공 200 `{"ok": true, "ssid", "bssid", "gateway"}`, 연결 없음 409 |
| POST | `/api/trust/forget` | 본문 `{"ssid": "Cafe"}`. 그 와이파이의 기준값을 지운다. 200, 없으면 404, ssid 빠지면 400 |
| POST | `/api/ack` | '확인함'. 지금 유효한 경보(`status.active`)를 비운다. `{"ok": true, "cleared": 개수, "ack_id"}`. 시스템 이벤트가 하나 남는다 |
| POST | `/api/demo` | `--demo` 로 켠 경우에만. 판단 상태를 비우고 데모 pcap을 재생. 202 시작, 409 이미 재생 중, 404 데모 꺼짐 |

`/api/learn` 은 "처음 본 값이 진짜"라고 가정하고 저장한다. 화면에서는 반드시 확인 창을 띄운다.
저장하면 ARP 판단을 새 기준값에서 다시 시작하고, 유효하던 ARP 경보는 비운다 (공유기 교체로 뜬 '주의' 정리용).

`/api/demo` 는 끝나면 판단 상태·공유기 주소·모듈 표시를 재생 전으로 되돌린다. 데모에서 나온 경보는
`active` 에 남아 있다가 '확인함'을 누르거나 10분이 지나면 빠진다.

`/api/status` 예

```json
{
  "overall": "warning", "overall_ko": "경고",
  "modules": {
    "arp": {"level": "normal",  "detail": "검사 중 (Wi-Fi)"},
    "dns": {"level": "normal",  "detail": "검사 중 (Wi-Fi)"},
    "ap":  {"level": "unknown", "detail": "주변 AP 목록을 읽지 못함 — …"}
  },
  "connection": {"ssid": "Cafe", "bssid": "88:36:6c:00:00:01", "auth": "WPA2-개인"},
  "gateway": {"ip": "192.168.0.1", "mac": "88:36:6c:00:00:01", "iface": "Wi-Fi"},
  "active": [
    {"module": "arp", "level": "warning", "title": "인터넷 해킹 의심", "event_id": 5,
     "last_seen": "2026-11-11T13:15:53+09:00"}
  ],
  "ack_id": 0,
  "score": {"score": 40, "grade": "위험", "reasons": ["ARP 스푸핑 경고가 있음 (−60)"]},
  "counts": {"warning": 1, "caution": 1, "unknown": 3},
  "trusted_ssids": ["Cafe"]
}
```

- `active`: **지금 유효한 경보**, 높은 단계부터. 같은 대상(ARP는 의심 MAC, AP는 SSID+BSSID, DNS는 도메인+기기)은
  하나로 묶는다. 근거가 계속 보이면 `last_seen` 이 갱신되고, 10분 동안 새 근거가 없으면 빠진다.
  `/api/ack` 로 비울 수 있고, 공격이 계속되면 다음 근거에서 제목 끝에 "(확인 후에도 계속됨)"이 붙어 다시 들어온다.
  서버를 다시 켜도 DB에서 복원된다. `event_id` 로 `/api/events` 의 해당 이벤트를 찾아 상세를 보여 줄 수 있다.
- `overall`: `active` 중 가장 높은 단계. 없으면 모듈 중 하나라도 `unknown` 이면 `unknown`, 아니면 `normal`.
- `modules[*].level`: 모듈이 **동작하는지**. 모듈 카드에 경보 색을 입히려면 `active` 에서 그 모듈의
  가장 높은 단계와 비교해 높은 쪽을 쓴다 (임시 대시보드 `app.js` 의 `renderModules` 참고).
- `modules.dns` 가 실시간 수집 중 2분 동안 UDP 53을 못 보면 `unknown` 이 된다 (보안 DNS·DoH 사용 추정).
- `score` 는 `active` 기준으로 계산한다 (확인했거나 오래된 경보는 감점하지 않는다).
- `connection`, `gateway` 는 없으면 `null`. `score.grade` 는 안전(80+)·주의(50+)·위험.

## Socket.IO

| 이벤트 | 방향 | 내용 |
|---|---|---|
| `status` | 서버 → 화면 | 접속하자마자 한 번, 그 뒤 상태가 바뀔 때마다. `/api/status` 와 같은 모양 |
| `event` | 서버 → 화면 | 새 이벤트 하나 |

화면에서 서버로 보내는 소켓 이벤트는 없다. 동작(스캔·저장·확인·데모)은 REST로 한다.
