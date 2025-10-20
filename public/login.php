<?php
// login.php — 兩步驟登入：先輸入學校信箱檢查是否存在，再輸入密碼(+自製圖片CAPTCHA)
// 依賴：/lib/auth.php 內已建立 $pdo 與 login_password_only($pdo, $email, $pwd)
// 依賴：同資料夾的 captcha.php 會用 $_SESSION['VerifyCode'] 產生圖片

// 建議在啟動 session 前設定 cookie 參數（避免 POST 後遺失 session、強化安全）
if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    ]);
}
session_start();

require_once __DIR__ . '/../lib/auth.php'; // 內含 $pdo、TOTP 等

// === CSRF（建議保留） ===
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['csrf'];

$msg = '';
$step = 1;               // 1=輸入 email、2=輸入密碼+CAPTCHA
$inputEmail = '';

// 小工具：產生 6 碼英數（大寫）
function gen_code(int $len = 6): string {
    $needBytes = (int)ceil($len / 2); // 每 2 bytes -> 4 hex chars
    return substr(strtoupper(bin2hex(random_bytes($needBytes))), 0, $len);
}

// 切換帳號：清掉 pending 與驗證碼（支援 GET 與 POST）
$wantChangeEmail =
    (isset($_GET['change_email'])) ||
    ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'change_email');

if ($wantChangeEmail) {
    unset($_SESSION['pending_login_email']);
    unset($_SESSION['VerifyCode']);
    $step = 1;
}

// 若已有 email，直接進入 Step 2 並保證有驗證碼
if (!empty($_SESSION['pending_login_email'])) {
    $step = 2;
    $inputEmail = $_SESSION['pending_login_email'];
    if (empty($_SESSION['VerifyCode'])) {
        $_SESSION['VerifyCode'] = gen_code(6);
    }
}

// 檢查帳號是否存在
function account_exists(PDO $pdo, string $email): bool {
    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    return (bool)$stmt->fetchColumn();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 可視需要啟用 CSRF 驗證
    // if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
    //     http_response_code(400); exit('Bad Request');
    // }

    $action = $_POST['action'] ?? '';

    if ($action === 'check_email') {
        // Step 1：輸入學校信箱
        $email = trim($_POST['email'] ?? '');
        $isSchoolMail = (bool) preg_match('/^[^@\s]+@o365\.ttu\.edu\.tw$/i', $email);

        if (!$isSchoolMail) {
            $msg = '請輸入 @o365.ttu.edu.tw 的學校信箱';
            $step = 1;
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $msg = '信箱格式不正確';
            $step = 1;
        } elseif (!account_exists($pdo, $email)) {
            $msg = '查無此帳號，請確認信箱是否正確或先註冊。';
            $step = 1;
        } else {
            $_SESSION['pending_login_email'] = $email;
            $_SESSION['VerifyCode'] = gen_code(6); // 進入 Step2 產生 6 碼圖形碼
            $step = 2;
            $inputEmail = $email;
        }
    }
    elseif ($action === 'submit_password') {
        // Step 2：密碼 + 圖形驗證碼一起送
        $email     = $_SESSION['pending_login_email'] ?? ($_POST['email_locked'] ?? '');
        $pwd       = $_POST['password'] ?? '';
        $codeInput = strtoupper(trim($_POST['captcha'] ?? ''));
        $codeSess  = strtoupper($_SESSION['VerifyCode'] ?? '');

        if ($email === '') {
            $msg = '請先輸入學校信箱';
            $step = 1;
        } else {
            // 先驗自製 CAPTCHA
            if ($codeSess === '' || !hash_equals($codeSess, $codeInput)) {
                $msg = '驗證碼錯誤，請再試一次';
                $step = 2;
                $inputEmail = $email;
                $_SESSION['VerifyCode'] = gen_code(6);
            } else {
                // 用過就失效
                unset($_SESSION['VerifyCode']);

                $loginResult = login_password_only($pdo, $email, $pwd);

                if ($loginResult !== false) {
                    // 密碼正確
                    unset($_SESSION['pending_login_email']);
                    $user = $loginResult;
                    /** @var array $user */

                    // 【最終版核心判斷邏輯】
                    if ($user['is_high_risk'] === 'Y') {
                        // 高風險：一定需要 TOTP
                        if ($user['is_first_login'] === 'Y') {
                            // A: 高風險 + 首次 -> 強制綁定
                            $_SESSION['force_totp_setup_user'] = [
                                'id' => $user['id'], 'email' => $user['email'], 'name' => $user['name']
                            ];
                            header('Location: ./force_totp_setup.php');
                            exit;
                        } else {
                            // B: 高風險 + 非首次 -> 一般 TOTP 驗證
                            $_SESSION['pending_user'] = [
                                'id' => $user['id'], 'email' => $user['email'], 'name' => $user['name']
                            ];
                            header('Location: ./totp_verify.php');
                            exit;
                        }
                    } else {
                        // C: 一般使用者 -> 直接登入
                        $_SESSION['user'] = [
                            'id'    => $user['id'],
                            'email' => $user['email'],
                            'name'  => $user['name'],
                        ];
                        log_login($pdo, $user['id'], $user['email'], true);
                        header('Location: ./dashboard.php');
                        exit;
                    }
                } else {
                    // 密碼錯誤
                    $msg = '密碼錯誤，請再試一次。';
                    $step = 2;
                    $inputEmail = $email;
                    $_SESSION['VerifyCode'] = gen_code(6);
                }
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
    <!-- Step 1：輸入學校信箱 -->
    <form method="post" action="./login.php" autocomplete="off">
      <input type="hidden" name="action" value="check_email">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
      <div class="row">
        <label>帳號</label>
        <input name="email" type="email" required
               pattern=".+@o365\.ttu\.edu\.tw$"
               value="<?= htmlspecialchars($inputEmail) ?>">
      </div>
      <button class="btn" type="submit">下一步</button>
    </form>

    <p class="muted"><a class="link" href="./forgot_password.php">忘記密碼？</a></p>

  <?php elseif ($step === 2): ?>
    <!-- Step 2：密碼 + 圖形 CAPTCHA -->
    <form method="post" action="./login.php" autocomplete="off" id="loginForm">
      <input type="hidden" name="action" value="submit_password">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">

      <div class="row">
        <label>學校信箱</label>
        <input type="email" value="<?= htmlspecialchars($inputEmail) ?>" disabled>
        <input type="hidden" name="email_locked" value="<?= htmlspecialchars($inputEmail) ?>">
        <div class="muted" style="margin-top:4px;">
          <!-- 改為純 GET 導頁，後端已支援 ?change_email=1 -->
          <a class="link" href="./login.php?change_email=1">不是你？更換帳號</a>
        </div>
      </div>

      <div class="row">
        <label>密碼</label>
        <div style="position:relative; display:inline-block; width:100%;">
          <input type="password" name="password" id="password" required style="width:100%; padding-right:30px;">
          <button type="button" id="togglePwd"
                  style="position:absolute; right:5px; top:5px; border:none; background:none; cursor:pointer;">
            👁️
          </button>
        </div>
        <div id="capsWarning" style="color:red; display:none; font-size:12px; margin-top:4px;">
          ⚠️ Caps Lock 已開啟
        </div>
      </div>

      <!-- CAPTCHA -->
      <div class="row">
        <label>驗證碼</label>
        <div class="captcha-group">
          <input name="captcha"
                 type="text"
                 inputmode="latin"
                 maxlength="6"
                 pattern="[A-Za-z0-9]{6}"
                 required
                 placeholder="輸入底下代碼"
                 class="captcha-input">
          <div class="captcha-visual">
            <!-- 改用同資料夾路徑 -->
            <img src="./captcha.php" id="captchaImg" alt="驗證碼" class="captcha-img" width="200" height="60">
            <button type="button" id="refresh-btn" aria-label="換一張" class="icon-btn" onclick="refreshCaptcha()">
              <svg viewBox="0 0 24 24" class="icon">
                <path d="M17.65 6.35A7.95 7.95 0 0 0 12 4a8 8 0 1 0 7.75 6h-2.1A6 6 0 1 1 12 6
                c1.3 0 2.5.42 3.47 1.13L13 9.6h7V2.6l-2.35 2.35z" fill="currentColor"></path>
              </svg>
            </button>
          </div>
        </div>
      </div>

      <button class="btn" type="submit">登入</button>
    </form>

    <p class="muted" style="margin-top:8px;">
      <a class="link" href="./forgot_password.php">忘記密碼？</a>
    </p>
  <?php endif; ?>

  <?php if ($msg): ?>
    <div class="msg"><?= htmlspecialchars($msg) ?></div>
  <?php endif; ?>
</div>

<script>
(function(){
  const pwdInput = document.getElementById('password');
  const toggleBtn = document.getElementById('togglePwd');
  const capsWarning = document.getElementById('capsWarning');

  if (pwdInput && toggleBtn) {
    // 顯示/隱藏密碼
    toggleBtn.addEventListener('click', () => {
      if (pwdInput.type === 'password') {
        pwdInput.type = 'text';
        toggleBtn.textContent = '🙈';
      } else {
        pwdInput.type = 'password';
        toggleBtn.textContent = '👁️';
      }
    });
    // Caps Lock 提示
    const updateCaps = (e) => {
      if (e.getModifierState && e.getModifierState('CapsLock')) {
        capsWarning.style.display = 'block';
      } else {
        capsWarning.style.display = 'none';
      }
    };
    pwdInput.addEventListener('keyup', updateCaps);
    pwdInput.addEventListener('keydown', updateCaps);
  }
})();

function refreshCaptcha(){
  const btn = document.getElementById('refresh-btn');
  const img = document.getElementById('captchaImg');
  if(!img) return;

  // 轉起來
  btn.classList.add('spin');

  // 換圖避免快取
  const base = img.dataset.base || img.src.split('?')[0];
  img.dataset.base = base;
  img.src = base + '?refresh=1&ts=' + Date.now();

  // 圖片載入完成（或失敗）才停轉
  const stop = () => {
    btn.classList.remove('spin');
    img.removeEventListener('load', stop);
    img.removeEventListener('error', stop);
  };
  img.addEventListener('load', stop);
  img.addEventListener('error', stop);
}
</script>
<?php include __DIR__ . '/../templates/footer.php'; ?>
