<?php
// 綁定用 6 碼驗證：成功→標記 token 使用→回登入頁
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php';
date_default_timezone_set('Asia/Taipei');

// 小型 TOTP 驗證（不碰你現有的 verify_totp_and_login）
function b32dec(string $b32): string {
  $alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $b32=strtoupper(preg_replace('/[^A-Z2-7]/','',$b32));
  $bits=''; for($i=0;$i<strlen($b32);$i++){ $v=strpos($alphabet,$b32[$i]); if($v!==false)$bits.=str_pad(decbin($v),5,'0',STR_PAD_LEFT); }
  $bin=''; for($i=0;$i+8<=strlen($bits);$i+=8){ $bin.=chr(bindec(substr($bits,$i,8))); }
  return $bin;
}
function totp_ok(string $secretB32, string $code, int $window=1, int $period=30): bool {
  if(!preg_match('/^\d{6}$/',$code)) return false;
  $secret=b32dec($secretB32); $t=(int)floor(time()/$period);
  for($i=-$window;$i<=$window;$i++){
    $ctr = pack('J',$t+$i); if(PHP_INT_SIZE===4){ $hi=($t+$i)>>32; $lo=($t+$i)&0xFFFFFFFF; $ctr=pack('N2',$hi,$lo); }
    $h = hash_hmac('sha1',$ctr,$secret,true); $o=ord($h[19])&0x0F;
    $bin=((ord($h[$o])&0x7F)<<24)|(ord($h[$o+1])<<16)|(ord($h[$o+2])<<8)|(ord($h[$o+3]));
    $otp=str_pad((string)($bin%1000000),6,'0',STR_PAD_LEFT);
    if(hash_equals($otp,$code)) return true;
  }
  return false;
}

$token = $_POST['token'] ?? '';  $code = trim($_POST['code'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/',$token)) { header('Location: ./login.php'); exit; }

$s = $pdo->prepare("SELECT * FROM email_magic_links WHERE token=? AND purpose='bind_totp' LIMIT 1");
$s->execute([$token]); $link = $s->fetch(PDO::FETCH_ASSOC);
if (!$link || $link['used_at'] || new DateTime() > new DateTime($link['expires_at'])) {
  exit('連結無效或已過期');
}
$userId = (int)$link['user_id'];

// 從 totp_secrets 取 secret
$q = $pdo->prepare("SELECT secret FROM totp_secrets WHERE user_id=? ORDER BY created_at DESC LIMIT 1");

$q->execute([$userId]); $row = $q->fetch(PDO::FETCH_ASSOC);
if (!$row) { exit('尚未產生 TOTP 祕鑰'); }
$secret = $row['secret'];

if (!totp_ok($secret, $code)) {
  header('Location: ./bind_totp_email.php?token='.$token.'&err='.urlencode('驗證碼錯誤')); exit;
}

// 標記此 magic link 已使用
$pdo->prepare("UPDATE email_magic_links SET used_at = NOW() WHERE id=?")->execute([$link['id']]);

// 成功 → 回登入頁（不自動登入）
header('Location: ./login.php?msg='.urlencode('綁定成功，請登入'));
exit;
