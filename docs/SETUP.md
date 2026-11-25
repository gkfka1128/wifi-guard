# 받아서 실행하고 프론트 연결하기

GitHub에서 받은 뒤 **백엔드를 띄우고, 프론트를 붙이는** 순서다.
Windows 10/11 기준이다. 명령은 모두 PowerShell에서 `wifi-guard` 폴더 안에서 실행한다.

| 하고 싶은 것 | 볼 곳 |
|---|---|
| 일단 화면에 데이터가 뜨는 걸 보고 싶다 | 1 → 2 → 3 |
| 내 프론트(React·Vite 등)를 붙이고 싶다 | 1 → 2 → 3 → 4 |
| 백엔드 없이 화면만 먼저 만들고 싶다 | 5 |
| 실제 와이파이를 감시하고 싶다 | 6 |
| 코드를 고쳐서 올리고 싶다 | 8 |

API의 자세한 형식은 [API.md](API.md)(설명)와 [openapi.json](openapi.json)(규격)에 있다.

---

## 1. 준비물

| 무엇 | 왜 | 확인 방법 |
|---|---|---|
| Python 3.11 이상 | 백엔드 실행 | `py --version` 또는 `python --version` |
| Git (없으면 ZIP으로 받아도 됨) | 코드 받기·올리기 | `git --version` |
| 크롬·엣지 | 화면 확인 | - |
| Npcap (6번에서만) | 실제 패킷 수집 | 데모만 볼 거면 필요 없음 |

Python이 없으면 https://www.python.org/downloads/ 에서 설치한다. 설치 첫 화면에서 **"Add python.exe to PATH"를 체크**한다.

## 2. 받기와 설치 (처음 한 번)

```powershell
git clone https://github.com/gkfka1128/wifi-guard.git
cd wifi-guard
```

Git이 없으면 저장소 페이지의 **Code → Download ZIP**으로 받아 압축을 풀고 그 폴더로 들어간다.

가상환경을 만들고 패키지를 설치한다.

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

`py` 가 없다고 나오면 `python -m venv .venv` 로 바꿔 쓴다.
이 문서의 명령은 가상환경을 켜지 않고 `.venv\Scripts\python` 을 직접 부르므로 `Activate.ps1` 은 필요 없다.

## 3. 데모로 실행해 보기

가장 쉬운 방법: **`demo.bat` 더블클릭** (관리자 권한·Npcap 필요 없음). 실시간 감시는 **`webstart.bat`** (관리자 권한으로 다시 열림). 일반 사용자용 안내는 [START-HERE.md](../START-HERE.md).

명령으로 켜려면:

```powershell
.venv\Scripts\python run_server.py --no-capture --demo
```

- 브라우저에서 **http://127.0.0.1:5000** 을 연다.
- 화면의 **데모 재생** 버튼을 누르면, 저장된 공격 시나리오 pcap(ARP 2종, DNS 1종)이 재생되고 경고가 뜬다.
- 백엔드 확인용 화면은 http://127.0.0.1:5000/debug 에 있다.
- 끌 때는 PowerShell에서 `Ctrl + C` 를 누른다.

`--no-capture` 는 실제 패킷 수집을 끄는 옵션이라 Npcap과 관리자 권한이 없어도 된다.
이때 ARP·DNS 카드가 '확인 불가'로 보이는 것은 정상이다. 데모를 재생하면 경고가 들어온다.

## 4. 내 프론트 연결하기

방법은 두 가지다. **개발하는 동안은 B, 시연할 때는 A**를 권장한다.

### A. 백엔드가 프론트 파일을 같이 내보내기

프론트를 빌드한 폴더(예: Vite의 `dist`)를 지정한다.

```powershell
.venv\Scripts\python run_server.py --no-capture --demo --frontend C:\경로\내프론트\dist
```

http://127.0.0.1:5000 에서 내 프론트가 열린다. 같은 주소라서 CORS 설정이 필요 없다. API 주소는 `""`(같은 서버)로 쓴다.

### B. 프론트 개발 서버를 따로 띄우기 (Vite·React·Live Server)

백엔드는 3번처럼 띄워 두고, 프론트 개발 서버를 따로 켠다.
아래 주소는 기본으로 허용돼 있어서 설정할 것이 없다.

- `http://localhost` 또는 `http://127.0.0.1` 의 포트 **3000, 5173, 5500, 8080**

다른 포트를 쓰면 백엔드를 켤 때 추가한다.

```powershell
.venv\Scripts\python run_server.py --no-capture --demo --allow-origin http://localhost:4200
```

API 주소는 `http://127.0.0.1:5000` 으로 쓴다.

### 연결 코드

**가장 쉬운 방법: `frontend/wifiguard-client.js` 를 가져다 쓴다.**
POST 헤더, 실시간 연결, 끊겼을 때 폴링 대체를 이 파일이 처리한다.

```html
<script src="http://127.0.0.1:5000/vendor/socket.io.min.js"></script>  <!-- 백엔드가 준다 (인터넷 없어도 됨) -->
<script src="wifiguard-client.js"></script>
<script>
  const guard = WifiGuard.connect({
    base: "http://127.0.0.1:5000",   // A 방법이면 ""
    onStatus: (status) => { /* 전체 상태: status.overall, status.active, status.modules ... */ },
    onEvents: (list) => { /* 처음 한 번: 최근 이벤트 목록 (최신순) */ },
    onEvent:  (event) => { /* 새 이벤트 하나 */ },
    onLink:   (state) => { /* "socket" | "polling" | "offline" */ },
  });

  // 버튼에 연결
  guard.demo();          // 데모 재생
  guard.scan();          // 주변 AP 지금 스캔
  guard.ack();           // '확인함'
  guard.learn();         // 지금 와이파이를 기준값으로 저장 (확인 창 먼저!)
</script>
```

React 같은 번들러 프로젝트에서는 `wifiguard-client.js` 를 `public/` 에 넣고 `index.html` 에서 위처럼 불러온 뒤,
컴포넌트에서 `window.WifiGuard.connect(...)` 로 쓰면 된다.

**직접 `fetch` 로 부를 때**는 POST에 헤더를 꼭 붙인다. 없으면 403이 난다.

```js
const API = "http://127.0.0.1:5000";
const status = await fetch(`${API}/api/status`).then(r => r.json());
const events = await fetch(`${API}/api/events?limit=50`).then(r => r.json());
await fetch(`${API}/api/ack`, { method: "POST", headers: { "X-WifiGuard": "1" } });
```

### 꼭 지킬 것 세 가지

1. **서버가 준 글자는 `textContent` 로만 넣는다.** 와이파이 이름(SSID)은 주변 사람이 마음대로 정할 수 있어서
   `innerHTML` 에 넣으면 스크립트가 실행될 수 있다. React에서는 `dangerouslySetInnerHTML` 을 쓰지 않는다.
2. **`advice` 의 명령은 보여 주고 복사만 하게 한다.** 실행 버튼을 만들지 않는다.
3. **`learn` 버튼은 확인 창을 먼저 띄운다.** "지금 와이파이가 안전하다고 확신할 때만 저장하세요."

## 5. 백엔드 없이 화면 먼저 만들기

`docs/examples/` 의 JSON은 데모를 실제로 재생해서 받은 응답이다. 가짜 데이터로 그대로 쓰면 된다.

| 파일 | 어떤 API의 응답인가 |
|---|---|
| `status_start.json` | `GET /api/status` 처음 켰을 때 (경보 없음) |
| `status_alert.json` | `GET /api/status` 데모 재생 직후 (경고 여러 개) |
| `status_after_ack.json` | `GET /api/status` '확인함' 누른 뒤 |
| `events.json` | `GET /api/events` |
| `meta.json`, `trust.json`, `diagnostics.json` | 같은 이름의 GET |
| `scan.json`, `learn.json`, `ack.json` | 같은 이름의 POST |
| `error_*.json`, `forget_404.json` | 오류 응답 |

## 6. 실제 와이파이 감시 (시연·실험용)

1. **Npcap 설치:** https://npcap.com 에서 받는다. 설치할 때 **"WinPcap API-compatible Mode"를 체크**한다.
2. **와이파이 켜기:** 작업 표시줄의 와이파이를 켜고 연결한다.
3. **위치 권한 켜기:** 설정 → 개인 정보 및 보안 → 위치 → 켬. Windows 11에서는 이게 꺼져 있으면 주변 AP 목록을 못 읽는다.
4. **PowerShell을 관리자 권한으로 열고** 실행한다.

```powershell
.venv\Scripts\python -m guard.diagnose        # 환경 점검: 빠진 게 있으면 알려 준다
.venv\Scripts\python run_server.py            # 실시간 감시
.venv\Scripts\python run_server.py --iface Wi-Fi --gateway 192.168.0.1   # 인터페이스·공유기를 직접 지정
```

화면이 '확인 불가'면 대시보드의 **환경 점검** 패널이나 `guard.diagnose` 결과를 보고 빠진 것을 채운다.
이 프로그램은 패킷을 **읽기만** 하고 보내지 않는다. 공격 재현은 반드시 팀 실험망(직접 준비한 공유기)에서만 한다.

## 7. 테스트

```powershell
.venv\Scripts\python -m unittest discover tests
```

47개가 모두 `OK` 로 끝나야 한다. `ContractTest` 는 실제 응답이 `docs/openapi.json` 규격과 맞는지 본다.
API 응답을 바꿨는데 규격을 안 고치면 이 테스트가 깨진다. 그럴 땐 카톡방에 먼저 공유하고 규격을 같이 고친다.

## 8. 고쳐서 올리기 (협업자로 초대받은 경우)

```powershell
git pull                                  # 작업 전에 최신으로
git switch -c 내이름/작업내용              # 예: hyoseon/dashboard
# ... 수정 ...
.venv\Scripts\python -m unittest discover tests
git add -A
git commit -m "무엇을 왜 바꿨는지"
git push -u origin 내이름/작업내용
```

GitHub 저장소 페이지에서 **Pull request**를 만들면 서로 확인한 뒤 `main` 에 합친다.
`.venv`, `out/`(기록 DB), `trust.json`(내 와이파이 기준값)은 `.gitignore` 에 들어 있어서 올라가지 않는다.

## 9. 문제 해결

| 증상 | 원인과 해결 |
|---|---|
| `py` / `python` 을 찾을 수 없음 | Python 설치 때 PATH 체크를 안 함 → 다시 설치하며 체크 |
| `pip install` 중 오류 | `.venv\Scripts\python -m pip install --upgrade pip` 후 다시 설치 |
| 화면이 안 열림 | 주소가 `http://127.0.0.1:5000` 인지 확인. 서버 창에 오류가 있는지 확인 |
| 포트 사용 중 (`WinError 10048`) | 이미 켜 둔 서버가 있음 → 그 창을 `Ctrl + C`, 또는 `--port 5001` |
| POST가 403 | `X-WifiGuard: 1` 헤더 빠짐, 또는 허용 안 된 포트에서 부름 → `--allow-origin` |
| 브라우저 콘솔에 CORS 오류 | 프론트 주소가 허용 목록에 없음 → 4-B의 `--allow-origin` |
| 다른 PC·휴대폰에서 접속 안 됨 | 정상. 보안상 이 PC(127.0.0.1)에서만 열린다 |
| 연결 상태가 `polling` | Socket.IO 스크립트를 못 불러옴(`/vendor/socket.io.min.js` 경로 확인). 3초마다 갱신으로 동작하니 그대로 써도 됨 |
| ARP·DNS가 '확인 불가' | `--no-capture` 로 켰거나 Npcap·관리자 권한 없음 → 6번 |
| 가짜 AP가 '확인 불가' | 와이파이 꺼짐 또는 위치 권한 꺼짐 → 6번의 2·3 |
| 데모 버튼이 안 보임 | `--demo` 없이 켬 → 3번 명령으로 다시 실행 |
