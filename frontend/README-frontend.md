# WiFi Guard 프론트엔드 (블랙 + 블루)

백엔드 `docs/API.md` 규격에 맞춘 대시보드. 데이터 처리는 그대로 두고 화면·디자인만 새로 만들었다.

## 파일
- `index.html` — 화면 구조 (요소 id는 app.js가 그대로 사용)
- `style.css` — 블랙 바탕 + 블루 포인트. 상태색(정상/주의/경고/확인불가)은 의미 전달용으로 유지
- `app.js` — 백엔드 응답을 화면에 그림 (백엔드 팀 원본 그대로, 수정 금지 권장)
- `wifiguard-client.js` — 백엔드 통신 (소켓/폴링 자동 전환, 원본 그대로)

## 실행 (백엔드와 같이)
이 폴더 4개 파일을 백엔드 `wifi-guard-main/frontend/` 에 덮어쓰고 서버를 켜면
127.0.0.1:5000 에서 열린다. (백엔드 README/SETUP 참고)

## VS Code에서 디자인만 수정할 때
- 색/여백/글꼴 → `style.css` 의 `:root` 토큰부터 만지면 전체가 바뀐다
  - `--bg`(바탕 검정), `--brand`(포인트 블루), `--card`, `--ink`, `--sub`
  - 상태색 `--normal/--caution/--warning/--unknown` 은 의미가 있으니 함부로 바꾸지 말 것
- 요소 배치 → `index.html`. 단, 요소의 **id는 바꾸지 말 것** (app.js가 그 id로 화면을 채운다)
- app.js / wifiguard-client.js 는 백엔드 규격과 맞물려 있으니 건드리지 않는 걸 추천
