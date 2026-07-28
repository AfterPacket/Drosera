<?php
declare(strict_types=1);

/*
 * Contact form handler.
 *
 * Genuine-looking submissions are logged as possible phishing reconnaissance and
 * answered with a thank-you page. Submissions carrying injection payloads are
 * scored and tarpitted.
 *
 * Zero-trust: no mail is ever sent, no field reaches a shell, a database, or a
 * filesystem path, and every value is escaped before it is rendered back.
 */

require_once __DIR__ . '/../lib/drosera.php';

[$ip, $identity] = sb_bootstrap();

if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
    header('Location: /', true, 302);
    exit;
}

$fields = [
    'name'    => mb_substr((string)($_POST['name'] ?? ''), 0, 2000),
    'email'   => mb_substr((string)($_POST['email'] ?? ''), 0, 2000),
    'phone'   => mb_substr((string)($_POST['phone'] ?? ''), 0, 2000),
    'message' => mb_substr((string)($_POST['message'] ?? ''), 0, 5000),
];

log_request($ip, ['handler' => 'contact-form']);

$sqlPattern = '#(\bunion\b.{0,40}\bselect\b|\bselect\b.{0,40}\bfrom\b|\binsert\s+into\b'
    . '|\bdrop\s+table\b|\bor\b\s+1\s*=\s*1|\'\s*or\s*\'|--\s|/\*.*\*/|\bsleep\s*\('
    . '|\bbenchmark\s*\(|\bload_file\s*\(|\binto\s+outfile\b)#is';
$xssPattern = '#(<script\b|javascript:|onerror\s*=|onload\s*=|<iframe\b|<svg\b'
    . '|document\.cookie|<img[^>]+src\s*=\s*["\']?\s*x)#i';
$shellPattern = '#(\$\(|`|;\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b|\|\s*(bash|sh)\b'
    . '|&&\s*(cat|curl|wget)\b|/etc/passwd|/dev/tcp/)#i';
$phpPattern = '#(<\?php|\beval\s*\(|\bsystem\s*\(|\bexec\s*\(|\bshell_exec\s*\('
    . '|\bpassthru\s*\(|\bbase64_decode\s*\(|\bassert\s*\()#i';

$detections = [];
$oversized = false;

foreach ($fields as $name => $value) {
    if (mb_strlen($value) > 500) {
        $oversized = true;
    }
    if (preg_match($sqlPattern, $value)) {
        $detections['SQLI_BASIC'] = "{$name}: " . mb_substr($value, 0, 200);
    }
    if (preg_match($xssPattern, $value)) {
        $detections['PHP_EVAL_ATTEMPT'] = "{$name} (XSS): " . mb_substr($value, 0, 200);
    }
    if (preg_match($shellPattern, $value)) {
        $detections['REVERSE_SHELL'] = "{$name} (shell): " . mb_substr($value, 0, 200);
    }
    if (preg_match($phpPattern, $value)) {
        $detections['PHP_EVAL_ATTEMPT'] = "{$name} (PHP): " . mb_substr($value, 0, 200);
    }
}

if ($oversized && $detections === []) {
    $detections['RATE_LIMIT_ABUSE'] = 'oversized contact form field (>500 chars)';
}

if ($detections !== []) {
    foreach ($detections as $eventType => $payload) {
        score_event($ip, $eventType, $payload);
    }
    activate_tarpit($ip, 'Injection payload in contact form');
    // A convincing, slow response -- as if the form did real work.
    sleep(2);
} else {
    // Clean submission: still evidence. Recon often precedes a phishing pretext.
    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => 'CONTACT_FORM_SUBMISSION',
        'reason' => 'Contact form submitted (no mail sent)',
        'name' => mb_substr($fields['name'], 0, 200),
        'email' => mb_substr($fields['email'], 0, 200),
        'phone' => mb_substr($fields['phone'], 0, 100),
        'payload_excerpt' => mb_substr($fields['message'], 0, 500),
        'headers' => sb_request_headers(),
    ]);
}

$displayName = trim($fields['name']) !== '' ? $fields['name'] : 'there';

header('Content-Type: text/html; charset=UTF-8');
header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Thank You &ndash; <?= sb_html(COMPANY_NAME) ?></title>
<meta name="generator" content="WordPress 6.4.3">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;color:#333;line-height:1.6;background:#fff}
header{background:#1a2744;color:#fff;padding:1.25rem 2rem;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:1.35rem;font-weight:700;letter-spacing:-.5px}
.logo span{color:#7ea2e0}
nav a{color:#cfd8ea;text-decoration:none;margin-left:1.5rem;font-size:.95rem}
nav a:hover{color:#fff}
main{max-width:720px;margin:0 auto;padding:4rem 2rem}
.card{border:1px solid #e2e6ee;border-left:5px solid #3a5fa0;border-radius:6px;padding:2.5rem;background:#fafbfd}
h1{color:#1a2744;font-size:1.9rem;margin-bottom:1rem;letter-spacing:-.5px}
p{margin-bottom:1rem;color:#444}
.ref{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#eef1f7;padding:.2rem .5rem;border-radius:3px;font-size:.9rem;color:#1a2744}
a.btn{display:inline-block;margin-top:1.5rem;background:#3a5fa0;color:#fff;padding:.7rem 1.6rem;border-radius:4px;text-decoration:none;font-weight:600}
a.btn:hover{background:#2f4d85}
footer{border-top:1px solid #e2e6ee;margin-top:4rem;padding:2rem;text-align:center;color:#888;font-size:.85rem}
</style>
</head>
<body>
<header>
  <div class="logo"><?= sb_company_logo() ?></div>
  <nav>
    <a href="/">Home</a><a href="/#services">Services</a><a href="/#about">About</a>
    <a href="/blog/">Blog</a><a href="/#contact">Contact</a>
  </nav>
</header>
<main>
  <div class="card">
    <h1>Thank you, <?= sb_html($displayName) ?>!</h1>
    <p>We&rsquo;ve received your message and a member of our team will be in touch within one business day.</p>
    <p>Your reference number is <span class="ref"><?= sb_html(sb_company_ref()) ?>-<?= sb_html(strtoupper(substr(md5($ip . gmdate('Ymd')), 0, 8))) ?></span>. Please quote it if you need to follow up.</p>
    <p>If your enquiry is urgent, call us on <strong>(512) 555-0147</strong> during business hours (Mon&ndash;Fri, 9am&ndash;6pm CT).</p>
    <a class="btn" href="/">&larr; Back to homepage</a>
  </div>
</main>
<footer>
  &copy; <?= COMPANY_FOUNDED ?>&ndash;2024 <?= sb_html(COMPANY_NAME) ?> LLC &middot; <?= sb_html(COMPANY_ADDRESS) ?>
</footer>
</body>
</html>
