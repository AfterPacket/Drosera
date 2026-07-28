<?php
declare(strict_types=1);

/*
 * WordPress 6.4.x login page replica.
 *
 * Credentials are recorded as evidence and always rejected with the authentic
 * WordPress error text. Nothing is ever authenticated against anything.
 */

require_once __DIR__ . '/../lib/drosera.php';

[$ip, $identity] = sb_bootstrap();

$error = '';
$username = '';

if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) === 'POST') {
    $username = mb_substr((string)($_POST['log'] ?? ''), 0, 128);
    $password = mb_substr((string)($_POST['pwd'] ?? ''), 0, 128);

    log_request($ip, ['handler' => 'wp-login', 'attempted_user' => $username]);

    // Record the pair, then score it.
    $redis = sb_redis();
    $seenPasswords = 1;
    if ($redis->isReady()) {
        $key = 'hp:creds:' . sb_ip_hash($ip);
        $redis->lpush($key, json_encode([
            'timestamp' => gmdate('c'),
            'username' => $username,
            'password' => $password,
            'service' => 'wp-login',
        ]));
        $redis->ltrim($key, 0, 199);
        $redis->expire($key, IDENTITY_TTL);

        $entries = $redis->lrange($key, 0, 199);
        if (is_array($entries)) {
            $recent = [];
            foreach ($entries as $entry) {
                $decoded = json_decode((string)$entry, true);
                if (is_array($decoded) && isset($decoded['password'])) {
                    $recent[$decoded['password']] = true;
                }
            }
            $seenPasswords = count($recent);
        }
    }

    score_event($ip, 'CREDENTIAL_ATTEMPT', "{$username}:{$password}");

    if ($seenPasswords > 5) {
        score_event($ip, 'CREDENTIAL_SPRAY', "{$seenPasswords} distinct passwords");
        activate_tarpit($ip, 'wp-login credential spray');
    }

    $identity = get_or_create_identity($ip);

    // Authentic WordPress timing: a real bcrypt check is not instant.
    usleep(2000000);

    if ((float)($identity['score'] ?? 0) >= TARPIT_THRESHOLD) {
        activate_tarpit($ip, 'wp-login score threshold reached');
    }

    $safeUser = sb_html($username !== '' ? $username : 'admin');
    $error = "<strong>Error:</strong> The username <strong>{$safeUser}</strong> "
        . "is not registered on this site. If you are unsure of your username, try "
        . "your email address instead.";
}

$host = sb_html((string)($_SERVER['HTTP_HOST'] ?? COMPANY_DOMAIN));

header('Content-Type: text/html; charset=UTF-8');
header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
header('X-Frame-Options: SAMEORIGIN');
?>
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; <?= sb_html(COMPANY_NAME) ?> &#8212; WordPress</title>
<meta name='robots' content='max-image-preview:large, noindex, noarchive' />
<meta name="viewport" content="width=device-width" />
<link rel='stylesheet' id='dashicons-css'  href='/wp-includes/css/dashicons.min.css?ver=6.4.3' media='all' />
<link rel='stylesheet' id='buttons-css'  href='/wp-includes/css/buttons.min.css?ver=6.4.3' media='all' />
<link rel='stylesheet' id='forms-css'  href='/wp-admin/css/forms.min.css?ver=6.4.3' media='all' />
<link rel='stylesheet' id='login-css'  href='/wp-admin/css/login.min.css?ver=6.4.3' media='all' />
<style>
html{background:#f0f0f1}
body.login{background:#f0f0f1;color:#3c434a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4;margin:0;padding:0;min-width:0}
#login{width:320px;padding:8% 0 0;margin:auto}
.login h1{text-align:center}
.login h1 a{background-image:url(/wp-admin/images/wordpress-logo.svg);background-size:84px;background-position:center top;background-repeat:no-repeat;color:#3c434a;height:84px;font-size:20px;font-weight:400;line-height:1.3;margin:0 auto 25px;padding:0;text-decoration:none;width:84px;text-indent:-9999px;outline:0;overflow:hidden;display:block}
.login form{margin-top:20px;margin-left:0;padding:26px 24px;font-weight:400;overflow:hidden;background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.login label{color:#3c434a;font-size:14px}
.login form .forgetmenot{font-weight:400;float:left;margin-bottom:0}
.login .button-primary{float:right;background:#2271b1;border-color:#2271b1;color:#fff;text-decoration:none;text-shadow:none;padding:0 12px;line-height:2.15384615;min-height:32px;border-radius:3px;border-width:1px;border-style:solid;cursor:pointer;font-size:13px}
.login input[type=text],.login input[type=password]{font-size:24px;line-height:1.33333333;width:100%;border:1px solid #8c8f94;background:#fff;box-shadow:0 0 0 transparent;border-radius:4px;padding:.1875rem .3125rem;margin:0 6px 16px 0;min-height:40px;box-sizing:border-box}
#login_error,.login .message,.login .success{border-left:4px solid #d63638;padding:12px;margin-left:0;margin-bottom:20px;background-color:#fff;box-shadow:0 1px 1px rgba(0,0,0,.04);word-wrap:break-word}
.login #nav,.login #backtoblog{font-size:13px;padding:0 24px;margin:24px 0 0}
.login #nav a,.login #backtoblog a{text-decoration:none;color:#50575e}
.login #nav a:hover,.login #backtoblog a:hover{color:#135e96}
.login .privacy-policy-page-link{text-align:center;width:100%;margin:3em 0 2em}
.clear{clear:both}
</style>
</head>
<body class="login no-js login-action-login wp-core-ui  locale-en-us">
<script>document.body.className = document.body.className.replace('no-js','js');</script>
	<div id="login">
		<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<?php if ($error !== ''): ?>
	<div id="login_error"><?= $error ?><br /></div>
<?php endif; ?>

		<form name="loginform" id="loginform" action="/wp-login.php" method="post">
			<p>
				<label for="user_login">Username or Email Address</label>
				<input type="text" name="log" id="user_login" class="input" value="<?= sb_html($username) ?>" size="20" autocapitalize="off" autocomplete="username" />
			</p>

			<div class="user-pass-wrap">
				<label for="user_pass">Password</label>
				<div class="wp-pwd">
					<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" />
				</div>
			</div>
			<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"  /> <label for="rememberme">Remember Me</label></p>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
				<input type="hidden" name="redirect_to" value="/wp-admin/" />
				<input type="hidden" name="testcookie" value="1" />
			</p>
		</form>

		<p id="nav">
			<a href="/wp-login.php?action=register">Register</a> |
			<a href="/wp-login.php?action=lostpassword">Lost your password?</a>
		</p>
		<p id="backtoblog">
			<a href="/">&larr; Go to <?= sb_html(COMPANY_NAME) ?></a>
		</p>
	</div>
	<script>
	try{document.getElementById('user_login').focus();}catch(e){}
	if(typeof wpOnload==='function')wpOnload();
	</script>
</body>
</html>
