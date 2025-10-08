<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) session_start();
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/totp.php';

/** 寫登入紀錄 */
function log_login(PDO $pdo, ?int $userId, ?string $email, bool $success): void {
    $ip = $_SERVER['REMOTE_ADDR']     ?? null;
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
    $stmt = $pdo->prepare('INSERT INTO login_logs (user_id, email, ip, user_agent, success) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$userId, $email, $ip, $ua, $success ? 1 : 0]);
}

/** 註冊：email 必須是 @o365.ttu.edu.tw，密碼兩次一致 */
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
function login_password_only(PDO $pdo, string $email, string $password): bool {
    $stmt = $pdo->prepare('SELECT id, email, name, password_hash FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([trim($email)]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        // 放入 pending 狀態，等 TOTP 通過才算登入完成
        $_SESSION['pending_user'] = [
            'id'    => (int)$user['id'],
            'email' => $user['email'],
            'name'  => $user['name'],
        ];
        return true;
    }
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
