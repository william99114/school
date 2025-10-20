<?php
declare(strict_types=1);// 啟用嚴格型別檢查，避免隱性型別轉換造成的錯誤
// 若尚未啟動 Session，則啟動；用於保存登入狀態與暫存 pending_user
if (session_status() === PHP_SESSION_NONE) session_start();// 啟動 Session（避免重複啟動）
require_once __DIR__ . '/../config/db.php'; // 載入資料庫連線（提供 $pdo）
require_once __DIR__ . '/totp.php';         // 載入 TOTP 工具（產生/驗證一次性密碼）


/** 寫登入紀錄 */
/**
 * 寫登入紀錄到 login_logs
 * @param PDO         $pdo     資料庫連線
 * @param int|null    $userId  使用者 ID（可能為 null，若用錯誤的 email 登入失敗）
 * @param string|null $email   使用者 Email（也可能為 null）
 * @param bool        $success 是否登入成功（true=成功 / false=失敗）
 */
function log_login(PDO $pdo, ?int $userId, ?string $email, bool $success): void {
    $ip = $_SERVER['REMOTE_ADDR']     ?? null;// 從伺服器變數取得來源 IP（可能為 null）
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;// 取得使用者代理（瀏覽器/裝置資訊）
     // 預先編譯 SQL，避免 SQL Injection，欄位對應：user_id, email, ip, user_agent, success
    $stmt = $pdo->prepare('INSERT INTO login_logs (user_id, email, ip, user_agent, success) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$userId, $email, $ip, $ua, $success ? 1 : 0]);
}

/** 註冊保留但不使用 */
function register_user(PDO $pdo, string $email, string $name, string $password, string $password2): array {
    $email = trim($email);
    $name  = trim($name);

    if (!preg_match('/^[A-Za-z0-9._%+-]+@o365\.ttu\.edu\.tw$/', $email)) {
        return [false, '必須使用學校信箱（@o365.ttu.edu.tw）'];
    }
    if ($password !== $password2) {
        return [false, '兩次輸入的密碼不一致'];
    }
    if (strlen($password) < 6) {
        return [false, '密碼至少 6 碼'];
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare('INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)');
        $stmt->execute([$email, $name, $hash]);
        $userId = (int)$pdo->lastInsertId();

        // 產生 TOTP 祕鑰並存檔
        $secret = totp_generate_secret();
        $stmt2 = $pdo->prepare('INSERT INTO totp_secrets (user_id, secret) VALUES (?, ?)');
        $stmt2->execute([$userId, $secret]);

        $pdo->commit();
        return [true, null, $userId, $secret];
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        if ($e->getCode() === '23000') return [false, '此信箱已註冊'];
        return [false, '資料庫錯誤'];
    }
}

/** 密碼驗證（不含 TOTP）成功則把 user 暫存到 session 並要求進行 TOTP 驗證 */
/**
 * 密碼驗證：
 * 成功時回傳使用者資料陣列 (包含 is_high_risk, is_first_login)
 * 失敗時回傳 false
 * @return array|false
 */
function login_password_only(PDO $pdo, string $email, string $password) {
    // ★ 修正：從資料庫查詢 is_high_risk 和 is_first_login 欄位
    $stmt = $pdo->prepare('
        SELECT id, email, name, password_hash, is_high_risk, is_first_login 
        FROM users 
        WHERE email = ? 
        LIMIT 1
    ');
    $stmt->execute([trim($email)]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        // ★ 修正：不再設定 SESSION，而是直接回傳使用者資料陣列
        return [
            'id'    => (int)$user['id'],
            'email' => $user['email'],
            'name'  => $user['name'],
            'is_high_risk' => $user['is_high_risk'] ?? 'N', // 預設為 'N'
            'is_first_login' => $user['is_first_login'] ?? 'N'  // 預設為 'N'
        ];
    }

    // 密碼錯誤或查無使用者，記錄失敗並回傳 false
    log_login($pdo, $user ? (int)$user['id'] : null, $email, false);
    return false;
}

/** 進行 TOTP 驗證，通過才正式登入 */
function verify_totp_and_login(PDO $pdo, string $code): bool {
    if (!isset($_SESSION['pending_user'])) return false;
    $u = $_SESSION['pending_user'];
    $stmt = $pdo->prepare('SELECT secret FROM totp_secrets WHERE user_id = ? LIMIT 1');
    $stmt->execute([$u['id']]);
    $row = $stmt->fetch();
    if (!$row) return false;

    if (totp_verify($row['secret'], $code)) {
        // 正式登入
        $_SESSION['user'] = $u;
        unset($_SESSION['pending_user']);
        log_login($pdo, $u['id'], $u['email'], true);
        return true;
    }
    return false;
}

/** 登入狀態 */
function is_logged_in(): bool { return isset($_SESSION['user']); }
function current_user(): ?array { return $_SESSION['user'] ?? null; }
function logout_user(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time()-42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}
