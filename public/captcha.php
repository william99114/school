<?php
// captcha.php — 6 碼、較大畫框（不每次重生，僅在沒有時才生成）
declare(strict_types=1);

// 建議：同站統一 cookie 範圍
session_set_cookie_params([
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
]);
session_start();

// ✅ 建議只在沒有 VerifyCode 時才生成，避免和 login.php 的流程互相覆蓋
if (empty($_SESSION['VerifyCode'])) {
    // 6 碼英數（A-Z0-9）
    $_SESSION['VerifyCode'] = substr(strtoupper(bin2hex(random_bytes(3))), 0, 6);
}

$code   = (string)$_SESSION['VerifyCode'];
$length = 6;

// 畫框放大（依長度自動算寬度）
$height = 60;
$cellW  = 32;                 // 每個字大約需要的寬度（可調）
$width  = max(180, $cellW * $length + 20);  // 左右余量 + 最小寬度保底

// 確認 GD
if (!function_exists('imagecreatetruecolor')) { http_response_code(500); exit('GD not available'); }

header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

$img = imagecreatetruecolor($width, $height);

// 背景與顏色
$bg     = imagecolorallocate($img, 255, 255, 255);
$black  = imagecolorallocate($img, 40, 40, 40);
imagefill($img, 0, 0, $bg);

// 干擾線
for ($i = 0; $i < 7; $i++) {
    $c = imagecolorallocate($img, mt_rand(150, 220), mt_rand(150, 220), mt_rand(150, 220));
    imageline($img, mt_rand(0,$width), mt_rand(0,$height), mt_rand(0,$width), mt_rand(0,$height), $c);
}
// 雜點
for ($i = 0; $i < 240; $i++) {
    $c = imagecolorallocate($img, mt_rand(180,240), mt_rand(180,240), mt_rand(180,240));
    imagesetpixel($img, mt_rand(0,$width-1), mt_rand(0,$height-1), $c);
}

// 嘗試 TTF，否則 fallback 內建字
$use_ttf = function_exists('imagettftext');
$font    = __DIR__ . '/LobsterTwo-Bold.otf';
if ($use_ttf && !is_readable($font)) $use_ttf = false;

if ($use_ttf) {
    // 每字的座標基準
    $fontSize = 26;                         // 字體大小（60 高度配 26 差不多）
    $baseY    = (int)($height * 0.70);      // 基線
    for ($i = 0; $i < $length; $i++) {
        $ch    = $code[$i];
        $angle = mt_rand(-15, 15);
        $x     = 10 + $i * $cellW + mt_rand(-2, 2);
        $color = imagecolorallocate($img, mt_rand(30,80), mt_rand(30,80), mt_rand(30,120));
        imagettftext($img, $fontSize, $angle, $x, $baseY, $color, $font, $ch);
    }
} else {
    // 內建字型置中排版
    $font    = 5; // 1~5
    $textW   = imagefontwidth($font) * strlen($code);
    $textH   = imagefontheight($font);
    $x       = (int)(($width - $textW) / 2);
    $y       = (int)(($height - $textH) / 2);
    imagestring($img, $font, $x, $y, $code, $black);
}

imagepng($img);
imagedestroy($img);
