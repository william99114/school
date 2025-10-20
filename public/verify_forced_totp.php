<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php';
require_once __DIR__ . '/../lib/totp.php';

// 安全檢查：如果 Session 中沒有待綁定的使用者資訊，就踢回登入頁
// 確保 session key 與登入頁面設定的一致，此處假設為 force_totp_setup_user
if (!isset($_SESSION['force_totp_setup_user'])) {
    header('Location: ./login.php');
    exit;
}

$user = $_SESSION['force_totp_setup_user'];
$userId = (int)$user['id'];
$code = trim($_POST['code'] ?? '');

// 從資料庫取得該使用者的 TOTP secret
$stmt = $pdo->prepare("SELECT secret FROM totp_secrets WHERE user_id = ? ORDER BY created_at DESC LIMIT 1");
$stmt->execute([$userId]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

// 驗證使用者輸入的 6 位數驗證碼是否正確
if (!$row || !totp_verify($row['secret'], $code)) {
    header('Location: ./force_totp_setup.php?err=' . urlencode('驗證碼錯誤，請再試一次'));
    exit;
}

// --- 驗證成功後的處理 ---
try {
    $pdo->beginTransaction();

    // 【關鍵修正】將欄位名稱從 force_totp_setup 改為 is_first_login
    $updateStmt = $pdo->prepare("UPDATE users SET is_first_login = 'N' WHERE id = ?");
    $updateStmt->execute([$userId]);
    
    // 建立正式的登入 Session
    $_SESSION['user'] = $user;
    
    // 清除暫時性的 Session
    unset($_SESSION['force_totp_setup_user']);

    // 寫入登入成功的紀錄
    log_login($pdo, $userId, $user['email'], true);

    $pdo->commit();

    // 導向到使用者主頁
    header('Location: ./dashboard.php');
    exit;

} catch (Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('無法完成首次登入設定: ' . $e->getMessage());
    header('Location: ./force_totp_setup.php?err=' . urlencode('系統發生錯誤，請稍後再試。'));
    exit;
}