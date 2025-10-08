<?php
// login.php — 兩步驟登入：先輸入學校信箱檢查是否存在，再輸入密碼
// 假設：lib/auth.php 內已建立 $pdo (PDO 連線) 與 login_password_only($pdo, $email, $pwd)

// 建議在啟動 session 前設定 cookie 參數，避免某些環境 POST 後遺失 session
if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

// 啟動 session
session_start();

require_once __DIR__ . '/../lib/auth.php';

// === CSRF 代碼（可暫時拿掉，但建議保留以防跨站請求攻擊） ===
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['csrf'];

$msg = '';
$step = 1; // 1 = 輸入 email、2 = 輸入密碼
$inputEmail = '';

// 使用者若點擊「更換帳號」
if (isset($_GET['change_email'])) {
    unset($_SESSION['pending_login_email']);
    $step = 1;
}

// 如果 session 中已有 email，直接顯示第 2 步
if (!empty($_SESSION['pending_login_email'])) {
    $step = 2;
    $inputEmail = $_SESSION['pending_login_email'];
}

// 檢查帳號是否存在
function account_exists(PDO $pdo, string $email): bool {
    $sql = 'SELECT id FROM users WHERE email = ? LIMIT 1';
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$email]);
    return (bool) $stmt->fetchColumn();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // === 這裡的 CSRF 驗證可以暫時移除，方便開發 ===
    $action = $_POST['action'] ?? '';

    if ($action === 'check_email') {
        // 第一步：輸入學校信箱
        $email = trim($_POST['email'] ?? '');
        $inputEmail = $email;

        $isSchoolMail = (bool) preg_match('/^[^@\s]+@o365\.ttu\.edu\.tw$/i', $email);
        if (!$isSchoolMail) {
            $msg = '請輸入 @o365.ttu.edu.tw 的學校信箱';
            $step = 1;
        } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $msg = '信箱格式不正確';
            $step = 1;
        } else if (!account_exists($pdo, $email)) {
            $msg = '查無此帳號，請確認信箱是否正確或先註冊。';
            $step = 1;
        } else {
            $_SESSION['pending_login_email'] = $email;
            $step = 2;
        }
    }
    elseif ($action === 'submit_password') {
        // 第二步：輸入密碼

        // 🔑 修正：除了讀 session，也讀取 hidden 欄位備援
        $email = $_SESSION['pending_login_email'] ?? ($_POST['email_locked'] ?? '');
        $pwd   = $_POST['password'] ?? '';

        if ($email === '') {
            $msg = '請先輸入學校信箱';
            $step = 1;
        } else {
            if (login_password_only($pdo, $email, $pwd)) {
                unset($_SESSION['pending_login_email']);
                header('Location: ./totp_verify.php');
                exit;
            } else {
                $msg = '密碼錯誤，請再試一次。';
                $step = 2;
                $inputEmail = $email; // 顯示鎖定的 email
            }
        }
    }
}

$pageTitle = '登入';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2>登入</h2>

  <?php if ($step === 1): ?>
    <!-- 第 1 步：輸入學校信箱 -->
    <form method="post" autocomplete="off">
      <input type="hidden" name="action" value="check_email">

      <div class="row">
        <label>學校信箱</label>
        <input name="email" type="email" required pattern=".+@o365\.ttu\.edu\.tw$" value="<?= htmlspecialchars($inputEmail) ?>">
      </div>
      <button class="btn" type="submit">下一步</button>
    </form>

    <p>沒有帳號？<a class="link" href="./register.php">去註冊</a></p>
    <p class="muted"><a class="link" href="./forgot_password.php">忘記密碼？</a></p>

  <?php elseif ($step === 2): ?>
    <!-- 第 2 步：輸入密碼 -->
    <form method="post" autocomplete="off">
      <input type="hidden" name="action" value="submit_password">

      <div class="row">
        <label>學校信箱</label>
        <!-- 顯示 email 並用 hidden 傳回，避免 session 遺失 -->
        <input type="email" value="<?= htmlspecialchars($inputEmail) ?>" disabled>
        <input type="hidden" name="email_locked" value="<?= htmlspecialchars($inputEmail) ?>">
        <div class="muted" style="margin-top:4px;">
          <a class="link" href="?change_email=1">不是你？更換帳號</a>
        </div>
      </div>

      <div class="row">
        <label>密碼</label>
        <input type="password" name="password" required>
      </div>

      <button class="btn" type="submit">登入並進行第二步驟</button>
    </form>

    <p class="muted" style="margin-top:8px;">
      <a class="link" href="./forgot_password.php">忘記密碼？</a>
    </p>
  <?php endif; ?>

  <?php if ($msg): ?>
    <div class="msg"><?= htmlspecialchars($msg) ?></div>
  <?php endif; ?>
</div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
