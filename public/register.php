<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php';
require_once __DIR__ . '/../lib/totp.php';

// ----- 需要快速看錯誤可暫時打開（測完關掉） -----
// ini_set('display_errors','1');
// error_reporting(E_ALL);

function app_base_url(): string {
  if (!empty($_ENV['APP_URL'])) return rtrim($_ENV['APP_URL'], '/');
  $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
          || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
  $scheme = $isHttps ? 'https' : 'http';
  $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
  return $scheme.'://'.$host;
}

$msg = '';
$ok  = false;

// 給前端回填
$emailValLocal = '';
$emailValCross = '';
$nameValLocal  = '';
$nameValCross  = '';
$schoolVal     = '';
$stuIdVal      = '';
$activeTab     = 'local'; // local | cross

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userType = $_POST['user_type'] ?? 'local'; // local or cross
    $activeTab = ($userType === 'cross') ? 'cross' : 'local';

    $email = trim($_POST['email'] ?? '');
    $name  = trim($_POST['name']  ?? '');
    $pwd1  = (string)($_POST['password']  ?? '');
    $pwd2  = (string)($_POST['password2'] ?? '');

    if ($userType === 'local') {
        $emailValLocal = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
        $nameValLocal  = htmlspecialchars($name,  ENT_QUOTES, 'UTF-8');

        // 本校學生：限制網域
        if (!preg_match('/@o365\.ttu\.edu\.tw$/i', $email)) {
            $msg = '本校學生限定使用 @o365.ttu.edu.tw 信箱。';
            $ok  = false;
        }
    } else {
        // 跨校學生：不限網域，只檢查必填欄位
        $emailValCross = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
        $nameValCross  = htmlspecialchars($name,  ENT_QUOTES, 'UTF-8');

        $schoolRaw     = trim($_POST['school_name'] ?? '');
        $studentRaw    = trim($_POST['student_id']  ?? ''); // 選填
        $schoolVal     = htmlspecialchars($schoolRaw, ENT_QUOTES, 'UTF-8');
        $stuIdVal      = htmlspecialchars($studentRaw, ENT_QUOTES, 'UTF-8');

        if ($schoolRaw === '') {
            $msg = '跨校學生請填寫就讀學校。';
            $ok  = false;
        }
    }

    if ($msg === '') {
        // 你的既有註冊：回傳 [$ok, $err, $uid, $secret]
        if ($userType === 'cross' && function_exists('register_user_cross')) {
            // 使用跨校專用註冊（school_name 必填；student_id 可為空字串）
            [$ok, $err, $uid, $secret] = register_user_cross(
                $pdo, $email, $name, $pwd1, $pwd2,
                $_POST['school_name'] ?? '', $_POST['student_id'] ?? ''
            );
        } else {
            // 沒有跨校專用函式就沿用原本 register_user（可在函式內忽略額外欄位）
            [$ok, $err, $uid, $secret] = register_user($pdo, $email, $name, $pwd1, $pwd2);
        }

        if ($ok) {
            // 產一次性 token（24 小時）
            $rawToken = bin2hex(random_bytes(32));
            $exp      = (new DateTime('+24 hours'))->format('Y-m-d H:i:s');

            $pdo->prepare("
              INSERT INTO email_magic_links (user_id, token, purpose, expires_at, ip, user_agent)
              VALUES (?, ?, 'bind_totp', ?, ?, ?)
            ")->execute([
              $uid,
              $rawToken,
              $exp,
              $_SERVER['REMOTE_ADDR']     ?? null,
              $_SERVER['HTTP_USER_AGENT'] ?? null
            ]);

            $link = app_base_url().'/auth2fa/public/bind_totp_email.php?token='.$rawToken;

            // 寄信：相容舊/新版 mailer（bool 或 [bool,string]）
            $sent = false; $mailErr = '';
            try {
              require_once __DIR__ . '/../lib/mailer.php'; // 內含 send_mail_o365_bind()

              if (function_exists('send_mail_o365_bind')) {
                // 可把 userType 與跨校資訊帶給 mailer 做樣板分流
                $res = send_mail_o365_bind($email, $link, [
                  'userType' => $userType,
                  'school'   => $_POST['school_name'] ?? null,
                  'studentId'=> $_POST['student_id']  ?? null,
                ]);
                if (is_array($res)) {
                  $sent    = (bool)($res[0] ?? false);
                  $mailErr = (string)($res[1] ?? '');
                } else {
                  $sent = (bool)$res;
                }
              } else {
                $mailErr = 'send_mail_o365_bind() 未定義';
                error_log($mailErr);
              }
            } catch (Throwable $e) {
              $mailErr = 'mailer exception: '.$e->getMessage();
              error_log($mailErr);
            }

            if ($sent) {
              $msg = ($userType === 'local')
                   ? '註冊成功！已寄出綁定信到您的 O365 信箱，請於 24 小時內點擊郵件中的按鈕完成綁定。'
                   : '註冊成功！已寄信至您填寫的信箱，請於 24 小時內點擊郵件中的按鈕完成綁定。';
            } else {
              $msg = '註冊成功，但郵件寄送失敗：' . htmlspecialchars($mailErr ?: 'unknown error', ENT_QUOTES, 'UTF-8');
            }
        } else {
            $msg = $err ?? '註冊失敗';
        }
    }
}

$pageTitle = '註冊';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2>註冊</h2>

  <!-- 上方分流 Tab -->
  <div style="display:flex; gap:8px; margin:10px 0 18px;">
    <button type="button" class="tabBtn" data-tab="local"
            style="padding:8px 14px;border-radius:999px;border:1px solid #e5e7eb;cursor:pointer;<?= $activeTab==='local' ? 'background:#eef2ff;border-color:#c7d2fe;color:#3730a3;font-weight:700;' : 'background:#f9fafb;' ?>">
      本校學生
    </button>
    <button type="button" class="tabBtn" data-tab="cross"
            style="padding:8px 14px;border-radius:999px;border:1px solid #e5e7eb;cursor:pointer;<?= $activeTab==='cross' ? 'background:#eef2ff;border-color:#c7d2fe;color:#3730a3;font-weight:700;' : 'background:#f9fafb;' ?>">
      跨校學生
    </button>
  </div>

  <?php if ($msg): ?>
    <div class="msg"><?= htmlspecialchars($msg) ?></div>
  <?php endif; ?>

  <!-- 本校學生表單 -->
  <form id="form-local" method="post" autocomplete="off" <?= $activeTab==='local' ? '' : 'style="display:none;"' ?>>
    <input type="hidden" name="user_type" value="local">
    <h3>（本校學生限定 @o365.ttu.edu.tw）</h3>

    <div class="row">
      <label>學校信箱</label>
      <input name="email" type="email" required pattern=".+@o365\.ttu\.edu\.tw$" value="<?= $emailValLocal ?>">
    </div>

    <div class="row">
      <label>姓名</label>
      <input name="name" type="text" placeholder="請輸入中文姓名" pattern="[\u4e00-\u9fa5]{2,5}" required value="<?= $nameValLocal ?>">
    </div>

    <div class="row">
      <label>密碼（至少 8 碼）</label>
      <input name="password" type="password" minlength="8" required>
    </div>
    <div class="row">
      <label>再次輸入密碼</label>
      <input name="password2" type="password" minlength="8" required>
    </div>
    <button class="btn" type="submit">建立帳號（本校）</button>
  </form>

  <!-- 跨校學生表單 -->
  <form id="form-cross" method="post" autocomplete="off" <?= $activeTab==='cross' ? '' : 'style="display:none;"' ?>>
    <input type="hidden" name="user_type" value="cross">
    <h3>（跨校學生不限網域，需填就讀學校）</h3>

    <div class="row">
      <label>電子信箱</label>
      <input name="email" type="email" required value="<?= $emailValCross ?>">
      <small style="color:#6b7280;font-size:0.9em;">可使用任何信箱，例如 Gmail、Yahoo</small>
    </div>

    <div class="row">
      <label>姓名</label>
      <input name="name" type="text" placeholder="請輸入中文姓名"
             pattern="[\u4e00-\u9fa5]{2,5}" required value="<?= $nameValCross ?>">
    </div>

    <div class="row">
      <label>就讀學校</label>
      <input name="school_name" type="text" required value="<?= $schoolVal ?>">
    </div>

    <!-- 若未來要把學號改為必填，把 required 打開即可 -->
    <!--
    <div class="row">
      <label>學號（選填）</label>
      <input name="student_id" type="text" value="<?= $stuIdVal ?>">
    </div>
    -->

    <div class="row">
      <label>密碼（至少 8 碼）</label>
      <input name="password" type="password" minlength="8" required>
    </div>
    <div class="row">
      <label>再次輸入密碼</label>
      <input name="password2" type="password" minlength="8" required>
    </div>
    <button class="btn" type="submit">建立帳號（跨校）</button>
  </form>

  <p style="margin-top:8px;">已經有帳號？<a class="link" href="./login.php">去登入</a></p>
</div>

<script>
// 前端 tab 切換
document.querySelectorAll('.tabBtn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab; // local | cross
    // 顯示/隱藏表單
    document.getElementById('form-local').style.display = (tab === 'local') ? '' : 'none';
    document.getElementById('form-cross').style.display = (tab === 'cross') ? '' : 'none';
    // 高亮按鈕
    document.querySelectorAll('.tabBtn').forEach(b => {
      const active = (b.dataset.tab === tab);
      b.style.background   = active ? '#eef2ff' : '#f9fafb';
      b.style.borderColor  = active ? '#c7d2fe' : '#e5e7eb';
      b.style.color        = active ? '#3730a3' : 'inherit';
      b.style.fontWeight   = active ? '700' : '400';
    });
  });
});
</script>

<?php include __DIR__ . '/../templates/footer.php'; ?>
