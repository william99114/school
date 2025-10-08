<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php'; // $pdo, session_start()

header('Content-Type: text/html; charset=utf-8');

// --- CSRF 檢查 ---
if (($_POST['csrf_token'] ?? '') !== ($_SESSION['csrf_token'] ?? '')) {
  http_response_code(400);
  exit('CSRF token 無效');
}

// 取得 email
$email = trim((string)($_POST['email'] ?? ''));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  header('Location: ./bind_totp_email.php?err='.urlencode('信箱格式不正確'));
  exit;
}

// 查使用者
$stmt = $pdo->prepare("SELECT id, email FROM users WHERE email=? LIMIT 1");
$stmt->execute([$email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$user) {
  header('Location: ./bind_totp_email.php?err='.urlencode('查無此帳號'));
  exit;
}

$userId = (int)$user['id'];

// 節流（60 秒）
$key = 'resend_bind_totp_' . md5(strtolower($email));
if (!isset($_SESSION[$key])) $_SESSION[$key] = 0;
if (time() - (int)$_SESSION[$key] < 60) {
  header('Location: ./bind_totp_email.php?err='.urlencode('請稍候再試（太頻繁）'));
  exit;
}

// 產生新 token（64 hex）
$token = bin2hex(random_bytes(32));
$expires = (new DateTime('+24 hours'))->format('Y-m-d H:i:s');

// 寫入 magic link
$ins = $pdo->prepare("
  INSERT INTO email_magic_links (user_id, token, purpose, expires_at, created_at)
  VALUES (?, ?, 'bind_totp', ?, NOW())
");
$ins->execute([$userId, $token, $expires]);

// 組信中的 URL（依你的實際路徑）
$base = (function (): string {
  $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
          || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
  $scheme = $isHttps ? 'https' : 'http';
  $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
  return $scheme.'://'.$host;
})();
$linkUrl = $base . '/auth2fa/public/bind_totp_email.php?token=' . urlencode($token);

// 寄信（請改成你現有的寄信函式）
$subject = '綁定 Microsoft Authenticator 驗證連結';
$body = "您好，請在 24 小時內點擊以下連結完成綁定：<br>"
      . '<a href="'.$linkUrl.'">'.$linkUrl.'</a><br><br>'
      . '若非您本人操作，請忽略此信。';

// 例：sendMail($to, $subject, $html)
if (!function_exists('sendMail')) {
  // 你專案已有的就用原本的；這裡只是保底
  function sendMail($to, $subject, $html) { return false; }
}
$ok = sendMail($email, $subject, $body);

$_SESSION[$key] = time();

if ($ok) {
  header('Location: ./login.php?msg='.urlencode('已寄出驗證信，請前往信箱收信'));
} else {
  header('Location: ./bind_totp_email.php?err='.urlencode('寄送失敗，請稍後再試'));
}
exit;
