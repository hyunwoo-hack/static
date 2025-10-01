<!-- auto-redirect.html -->
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Auto redirect</title>
  <!-- meta refresh (fallback) -->
  <meta http-equiv="refresh" content="5;url=https://example.com/">
</head>
<body>
  <h3>Redirecting in 5s... (or immediately by JS)</h3>

  <script>
    // 즉시 리다이렉트
    const target = "https://naver.com
    window.location.href = target;
    // 또는: window.location.replace(target); (브라우저 히스토리 남기지 않음)
  </script>
</body>
</html>

