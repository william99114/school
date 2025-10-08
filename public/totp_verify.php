<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php';

if (!isset($_SESSION['pending_user'])) { header('Location: ./login.php'); exit; }

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = $_POST['code'] ?? '';
    if (verify_totp_and_login($pdo, $code)) {
        header('Location: ./dashboard.php'); exit;
    } else {
        $msg = '驗證碼錯誤或已過期，請再試一次';
    }
}

$pageTitle = '二步驟驗證';
include __DIR__ . '/../templates/header.php';
$u = $_SESSION['pending_user'];
?>
<div class="card">
  <h2>二步驟驗證</h2>
  <p>請輸入 <?=htmlspecialchars($u['email'])?> 的 6 位數驗證碼。</p>
  <form method="post" autocomplete="one-time-code">
    <div class="row">
      <label>驗證碼</label>
      <input name="code" inputmode="numeric" pattern="\d{6}" maxlength="6" required>
    </div>
    <button class="btn" type="submit">驗證並登入</button>
  </form>
  <?php if ($msg): ?><div class="msg"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <p style="margin-top:8px;"><a class="link" href="./login.php">返回登入</a></p>
</div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
