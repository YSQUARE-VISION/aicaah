# -*- coding: utf-8 -*-
"""첫 판정의 완료·실패·연결 상태를 조회하는 시작 화면."""


def page():
    """판정 결과가 준비되면 자동으로 지도를 다시 여는 HTML."""
    return """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>하네스 시작</title>
<noscript><meta http-equiv="refresh" content="2"></noscript></head>
<body><p id="startup-status" role="status">첫 판정 중…</p>
<p><a href="/map">지도 다시 열기</a></p>
<script>
(() => {
  const label = document.getElementById("startup-status");
  let navigating = false;
  const poll = async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch("/status", {cache: "no-store", signal: controller.signal});
      if (!response.ok) throw new Error("HTTP " + response.status);
      const state = await response.json();
      if (state.error) label.textContent = "첫 판정 실패. 서버 로그를 확인하세요.";
      else if (state.rev !== null && state.rev !== undefined && !state.busy) {
        navigating = true;
        location.reload();
      } else label.textContent = "첫 판정 중… 완료되면 자동으로 지도를 엽니다.";
    } catch (error) {
      label.textContent = "서버 연결을 기다리는 중… 자동으로 다시 확인합니다.";
    } finally {
      clearTimeout(timer);
      if (!navigating) setTimeout(poll, 1000);
    }
  };
  poll();
})();
</script></body></html>"""
