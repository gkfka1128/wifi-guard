"""F5  기록과 대시보드.

events.jsonl 에 경고를 한 줄씩 쌓고, results.json 을 dashboard.html 로 그린다.
대시보드는 데이터를 HTML 안에 넣어 file:// 로 열어도 보이게 한다.
"""
import html
import json
import subprocess
import time
from pathlib import Path

from .arp_watch import tshark_path


def log_event(out_dir, event):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "events.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"logged": time.strftime("%Y-%m-%d %H:%M:%S"), **event},
                           ensure_ascii=False) + "\n")


def save_evidence(pcap, first, last, out_path, margin=20):
    """경고 전후 프레임만 잘라 증거 pcap으로 저장한다."""
    flt = f"frame.number >= {max(first - margin, 1)} && frame.number <= {last + margin}"
    subprocess.run([tshark_path(), "-r", pcap, "-Y", flt, "-w", str(out_path)], check=True)
    return str(out_path)


def write_results(out_dir, results):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    old = out_dir / "results.json"
    merged = json.loads(old.read_text(encoding="utf-8")) if old.exists() else {}
    merged.update(results)
    merged["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    old.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "dashboard.html").write_text(render(merged), encoding="utf-8")
    return merged


def _rows(items, cols):
    if not items:
        return '<p class="none">없음</p>'
    head = "".join(f"<th>{html.escape(c)}</th>" for c, _ in cols)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(get(i)))}</td>" for _, get in cols) + "</tr>"
                   for i in items)
    return f"<table><tr>{head}</tr>{body}</table>"


def render(r):
    s = r.get("score") or {"score": "–", "grade": "진단 전", "reasons": []}
    color = {"안전": "#1b7f5a", "주의": "#c98a14", "위험": "#c0392b"}.get(s["grade"], "#5c6b73")
    arp = _rows(r.get("arp_alerts", []), [
        ("단계", lambda a: a.get("level", "")), ("점수", lambda a: a["risk"]), ("대상 MAC", lambda a: a["mac"]),
        ("공격자 추정", lambda a: a.get("suspect") or "확인 필요"),
        ("근거", lambda a: " / ".join(a["reasons"])), ("방어", lambda a: " ; ".join(a.get("defense", [])) or "–")])
    ap = _rows(r.get("ap_alerts", []) + r.get("gateway_alerts", []), [
        ("점수", lambda a: a["risk"]), ("이름", lambda a: a["ssid"]), ("BSSID", lambda a: a["bssid"] or "(접속 후 확인)"),
        ("보안", lambda a: a["auth"]), ("근거", lambda a: " / ".join(a["reasons"]))])
    ev = _rows(r.get("evaluation", []), [
        ("위협", lambda e: e["threat"]), ("시나리오", lambda e: e["runs"]),
        ("탐지율", lambda e: f'{e["detection_rate"]:.0%}'), ("오탐", lambda e: f'{e["false_alarms"]}/{e["normal_runs"]}'),
        ("평균 탐지 시간", lambda e: f'{e["mean_delay_s"]:.2f}초' if e["mean_delay_s"] is not None else "–")])
    reasons = "".join(f"<li>{html.escape(x)}</li>" for x in s["reasons"]) or "<li>감점 항목 없음</li>"
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>와이파이 지킴이</title>
<style>
body{{font-family:"Malgun Gothic",sans-serif;margin:0;padding:24px;background:#f6f8f9;color:#1d2a30}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:16px;margin:28px 0 8px;color:#0b3c49}}
.sub{{color:#5c6b73;font-size:13px}} .card{{background:#fff;border:1px solid #dde3e6;padding:16px 20px;max-width:1100px}}
.score{{font-size:44px;font-weight:bold;color:{color}}} .grade{{font-size:18px;color:{color};margin-left:8px}}
table{{border-collapse:collapse;width:100%;font-size:13px;background:#fff}}
th,td{{border-bottom:1px solid #e3e8ea;padding:6px 8px;text-align:left;vertical-align:top}}
th{{color:#5c6b73;font-weight:normal;white-space:nowrap}} .none{{color:#5c6b73;font-size:13px}}
</style></head><body>
<h1>와이파이 지킴이</h1><div class="sub">마지막 갱신 {html.escape(r.get("updated", ""))}</div>
<h2>네트워크 안전 점수</h2><div class="card"><span class="score">{s["score"]}</span><span class="grade">{s["grade"]}</span>
<ul>{reasons}</ul></div>
<h2>ARP 스푸핑 경고</h2>{arp}
<h2>가짜 AP 경고</h2>{ap}
<h2>평가 결과</h2>{ev}
</body></html>"""
