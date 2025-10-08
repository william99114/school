<?php
declare(strict_types=1);
session_start();

/* 偵錯用（上線請關） */
error_reporting(E_ALL);
ini_set('display_errors','1');
ini_set('log_errors','1');
ini_set('error_log','/var/log/php_errors.log');

/* （可選）為了顯示時間一致，設定 PHP 時區；真正比較過期用 DB 的 NOW()，不受這行影響 */
date_default_timezone_set('Asia/Taipei');

/** 統一表名（之後要改表名只用改這裡） */
define('PW_RESET_TABLE', 'password_resets');

require_once __DIR__ . '/../lib/auth.php';               // 應提供 $pdo (PDO 連線)
require_once __DIR__ . '/../include/mailer.php';         // send_mail()
require_once __DIR__ . '/../include/mail_templates.php'; // tpl_reset_password()

/** HTML escape */
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

$msg = $ok = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    // 只接受學校信箱
    if (!preg_match('/@o365\.ttu\.edu\.tw$/', $email)) {
        $msg = '請輸入學校信箱（@o365.ttu.edu.tw）';
    } else {
        // 找使用者（仍不洩漏是否存在）
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        // 對外統一訊息，避免帳號枚舉
        $ok = '若信箱存在，已寄出重設連結（30 分鐘內有效）。';

        if ($user) {
            $userId = (int)$user['id'];

            // 產生「明文 token」（寄給使用者）與其 SHA-256 雜湊（寫進資料庫）
            $token  = bin2hex(random_bytes(32));
            $hash   = hash('sha256', $token);

            // ⚠️ 重要：不要用 PHP 來算 expires_at，避免 PHP 與 MySQL 時區不同。
            // $exp = (new DateTimeImmutable('+30 minutes'))->format('Y-m-d H:i:s'); // ← 這行不要再用

            // 先把該使用者「尚未使用」的舊 token 作廢（標記已用並記錄時間）
            $pdo->prepare('UPDATE '.PW_RESET_TABLE.' SET used = 1, used_at = NOW() WHERE user_id = ? AND used = 0')
                ->execute([$userId]);

            // 取用戶端資訊（選填欄位：若你的表沒有 ip/user_agent 欄位，可把相關欄位與值拿掉）
            $ip = $_SERVER['REMOTE_ADDR']     ?? null;
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;

            // ✅ 用資料庫時間計算到期：DATE_ADD(NOW(), INTERVAL 30 MINUTE)
            // 這樣 expires_at 與後續查詢的 NOW() 都在 MySQL 的同一個時鐘上，不會「一產生就過期」
            $sql = '
                INSERT INTO '.PW_RESET_TABLE.'
                    (user_id, token_hash, expires_at, ip, user_agent)
                VALUES
                    (?,       ?,          DATE_ADD(NOW(), INTERVAL 30 MINUTE), ?,  ?)
            ';
            $pdo->prepare($sql)->execute([$userId, $hash, $ip, $ua]);

            // === 正確組重設連結（支援反向代理） ===
            $proto  = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
            $uriDir = rtrim(dirname($_SERVER['REQUEST_URI']), '/\\');
            $base   = $proto.'://'.$_SERVER['HTTP_HOST'].($uriDir === '.' ? '' : $uriDir);
            $link   = $base.'/reset_password.php?token='.urlencode($token);

            // 用模板產生信件內容，並透過共用 mailer 寄出
            [$subject, $html, $text] = tpl_reset_password($email, $link);
            try {
                send_mail($email, $subject, $html, $text);
            } catch (Throwable $e) {
                // 不把錯誤曝露給使用者，僅記錄以利偵錯
                error_log('Forgot mail send failed: '.$e->getMessage());
            }

            // 開發模式：在畫面顯示連結便於測試（正式環境請關掉 APP_ENV 或移除此段）
            if ((getenv('APP_ENV') ?: '') === 'local') {
                $ok .= '（開發模式）重設連結：<br><code>'.h($link).'</code>';
            }
        }
    }
}

// 頁面呈現（沿用你的模板）
$pageTitle = '重設密碼';
include __DIR__ . '/../templates/header.php';
?>
  <div class="card">
    <h2 class="title">重設密碼</h2>
    <?php if ($msg): ?><div class="msg"><?= h($msg) ?></div><?php endif; ?>
    <?php if ($ok):  ?><div class="msg ok"><?= $ok ?></div><?php endif; ?>

    <form method="post" autocomplete="off">
      <div class="row">
        <label for="email">學校信箱</label>
        <input class="input" id="email" name="email" type="email" required
               pattern=".+@o365\.ttu\.edu\.tw$" placeholder="xxx@o365.ttu.edu.tw">
      </div>
      <button class="btn primary" type="submit">寄送重設連結</button>
    </form>

    <p class="muted"><a class="link" href="./login.php">回登入</a></p>
  </div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
