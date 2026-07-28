<?php
declare(strict_types=1);

/*
 * Catch-all handler for every unmatched path.
 *
 * Known scanner probes get a convincing fake artefact whose credentials match
 * the honeytokens in index.html and the fake wp-config, so an attacker chasing
 * the thread stays inside the honeypot. Everything else gets a WordPress 404.
 *
 * Zero-trust: the request path is used only for pattern matching. It is never
 * resolved against a real file, passed to a shell, or included.
 */

require_once __DIR__ . '/../lib/drosera.php';

[$ip, $identity] = sb_bootstrap();

$path = strtolower((string)(parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/'));
$path = '/' . ltrim($path, '/');
$basename = basename($path);

log_request($ip, ['handler' => 'catch_scanner_paths']);

/** Probe patterns that identify an automated scanner rather than a visitor. */
const SCANNER_PATTERNS = [
    '#^/\.env#', '#^/\.git/#', '#^/\.svn/#', '#^/\.aws/#', '#^/\.ssh/#',
    '#wp-config\.php#', '#^/phpinfo\.php#', '#^/info\.php#', '#^/config\.php$#',
    '#^/configuration\.php#', '#^/\.htaccess#', '#^/\.htpasswd#',
    '#backup\.(sql|zip|tar\.gz|tgz)#', '#database\.sql#', '#dump\.sql#',
    '#^/adminer\.php#', '#^/phpmyadmin#', '#^/pma/#', '#^/mysql/#',
    '#^/(c99|r57|wso|b374k|alfa|indoxploit|mini|cmd|shell|up|adminer)\.php#',
    '#^/admin/?$#', '#^/administrator#', '#^/manager/html#',
    '#^/wp-content/plugins/#', '#^/wp-content/uploads/private/#',
    '#^/wp-includes/#', '#^/wp-admin/(?!admin-ajax\.php)#',
    '#^/backup/#', '#^/config/#', '#^/\.well-known/security\.txt$#',
    '#^/actuator#', '#^/api/v[0-9]+/swagger#', '#^/solr/#', '#^/cgi-bin/#',
    '#^/vendor/phpunit#', '#^/_ignition/#', '#^/telescope/#',
    '#^/server-status#', '#^/\.DS_Store#', '#credentials#',
];

$isScannerPath = false;
foreach (SCANNER_PATTERNS as $pattern) {
    if (preg_match($pattern, $path)) {
        $isScannerPath = true;
        break;
    }
}

if (!$isScannerPath) {
    render_wordpress_404();
    exit;
}

score_event($ip, 'SCANNER_PATH_HIT', $path);
activate_tarpit($ip, "Scanner path probed: {$path}");
$identity = get_or_create_identity($ip);

// --- large "download" baits: header, then trickle forever -------------------

if (preg_match('#(backup\.sql|database\.sql|dump\.sql|backup\.zip|backup\.tar\.gz)$#', $path)) {
    serve_sql_dump_tarpit($ip, $basename);
}

// --- convincing fake artefacts ---------------------------------------------

if (preg_match('#^/\.env#', $path)) {
    serve_plain(fake_env_file($identity));
}

if (preg_match('#^/\.git/config#', $path)) {
    serve_plain(fake_git_config());
}

if (preg_match('#^/\.git/HEAD#', $path)) {
    serve_plain("ref: refs/heads/main\n");
}

if (preg_match('#wp-config\.php#', $path)) {
    serve_plain(fake_wp_config_file($identity));
}

if (preg_match('#^/\.aws/credentials#', $path)) {
    serve_plain("[default]\naws_access_key_id = " . FAKE_AWS_KEY_ID . "\n"
        . "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\n"
        . "region = us-east-2\n\n[staging]\naws_access_key_id = "
        . FAKE_AWS_KEY_ID_STAGING . "\n"
        . "aws_secret_access_key = 8Qz1nR4vT7yU0iOpAsDfGhJkLzXcVbNm3456789A\n"
        . "region = us-west-1\n");
}

if (preg_match('#^/\.ssh/id_rsa#', $path)) {
    serve_plain("-----BEGIN OPENSSH PRIVATE KEY-----\n"
        . chunk_split(base64_encode(str_repeat(COMPANY_SLUG . '-deploy-key-placeholder-', 48)), 70, "\n")
        . "-----END OPENSSH PRIVATE KEY-----\n");
}

if (preg_match('#^/(phpinfo|info)\.php#', $path)) {
    serve_html(fake_phpinfo_page($identity));
}

if (preg_match('#^/adminer\.php#', $path)) {
    serve_html(adminer_login_page());
}

if (preg_match('#^/(phpmyadmin|pma|mysql)#', $path)) {
    serve_html(phpmyadmin_login_page());
}

if (preg_match('#^/(c99|r57|wso|b374k|alfa|indoxploit|mini|cmd|shell|up)\.php#', $path)) {
    // A "shell" an attacker thinks they or a predecessor planted.
    serve_html('<html><head><title>404 Not Found</title></head><body>'
        . '<h1>Not Found</h1><p>The requested URL was not found on this server.</p>'
        . '<hr><address>' . sb_html(FAKE_SERVER_SOFTWARE) . ' Server at '
        . sb_html((string)($_SERVER['HTTP_HOST'] ?? 'localhost')) . ' Port 80</address>'
        . '</body></html>', 404);
}

if (preg_match('#^/server-status#', $path)) {
    serve_plain("Apache Server Status for " . (string)($_SERVER['HTTP_HOST'] ?? 'localhost')
        . "\n\nServer Version: " . FAKE_SERVER_SOFTWARE
        . "\nServer Built: 2023-10-26T13:44:14\n\nCurrent Time: " . gmdate('r')
        . "\nRestart Time: Mon, 27 Nov 2023 04:51:12 UTC\nParent Server Config. Generation: 1\n"
        . "Server uptime: 47 days 3 hours 19 minutes\nTotal accesses: 8842193 - Total Traffic: 4.8 GB\n"
        . "1 requests currently being processed, 9 idle workers\n");
}

// Any other recognised scanner path: WordPress-style 404 (already scored).
render_wordpress_404();
exit;

// ============================================================== helpers

function serve_plain(string $body, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    echo $body;
    exit;
}

function serve_html(string $body, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    echo $body;
    exit;
}

/**
 * Serve an endless fake SQL dump at ~200 bytes/second.
 *
 * The client sees a plausible download that never finishes. Bounded by the same
 * concurrency cap and deadline as the main tarpit so it cannot starve PHP-FPM.
 */
function serve_sql_dump_tarpit(string $ip, string $filename): void
{
    $redis = sb_redis();
    $counterKey = 'hp:tarpit:concurrent';
    $slotTaken = false;

    if ($redis->isReady()) {
        $active = (int)$redis->incr($counterKey);
        $redis->expire($counterKey, TARPIT_MAX_SECONDS + 60);
        if ($active > TARPIT_MAX_CONCURRENT) {
            $redis->decr($counterKey);
            render_wordpress_404();
            exit;
        }
        $slotTaken = true;
    }
    $release = static function () use ($redis, $counterKey, &$slotTaken): void {
        if ($slotTaken && $redis->isReady()) {
            $redis->decr($counterKey);
            $slotTaken = false;
        }
    };
    register_shutdown_function($release);

    @ignore_user_abort(false);
    @set_time_limit(0);
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    header('HTTP/1.1 200 OK');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . preg_replace('/[^\w.-]/', '', $filename) . '"');
    header('Content-Length: 2147483648');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');

    echo "-- MySQL dump 10.13  Distrib 5.7.38, for Linux (x86_64)\n--\n"
        . "-- Host: localhost    Database: " . FAKE_DB_NAME . "\n"
        . "-- ------------------------------------------------------\n"
        . "-- Server version\t" . FAKE_MYSQL_VERSION . "\n\n"
        . "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
        . "/*!40103 SET TIME_ZONE='+00:00' */;\n\n"
        . "DROP TABLE IF EXISTS `wp_users`;\n"
        . "CREATE TABLE `wp_users` (\n"
        . "  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n"
        . "  `user_login` varchar(60) NOT NULL DEFAULT '',\n"
        . "  `user_pass` varchar(255) NOT NULL DEFAULT '',\n"
        . "  `user_email` varchar(100) NOT NULL DEFAULT '',\n"
        . "  PRIMARY KEY (`ID`)\n"
        . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n"
        . "LOCK TABLES `wp_users` WRITE;\n";
    @flush();

    $started = time();
    $deadline = $started + TARPIT_MAX_SECONDS;
    $row = 1;

    $surnames = ['marsh', 'kowalski', 'chen', 'okafor', 'bergman', 'nguyen',
                 'delgado', 'petrov', 'haddad', 'lindqvist'];

    while (!connection_aborted() && time() < $deadline) {
        $name = $surnames[array_rand($surnames)] . $row;
        echo sprintf(
            "INSERT INTO `wp_users` VALUES (%d,'%s','\$P\$B%s','%s@" . COMPANY_DOMAIN . "');\n",
            $row, $name, substr(md5((string)$row), 0, 30), $name
        );
        @flush();
        usleep(200000);   // ~200 bytes/second
        $row++;

        if ($row % 100 === 0) {
            sb_log_tarpit($ip, "SQL dump bait: {$filename}", time() - $started, $row,
                          'TARPIT_KEEPALIVE');
        }
    }

    sb_log_tarpit($ip, "SQL dump bait: {$filename}", time() - $started, $row);
    $release();
    exit;
}

function fake_env_file(array $identity): string
{
    // Every credential here is a honeytoken, and a honeytoken shared with every
    // other deployment tells you nothing when it surfaces. Persona-derived.
    return "APP_NAME=\"" . COMPANY_NAME . "\"\nAPP_ENV=production\n"
        . "APP_KEY=base64:" . FAKE_HONEYTOKEN_KEY . "\nAPP_DEBUG=false\n"
        . "APP_URL=https://" . (string)($_SERVER['HTTP_HOST'] ?? COMPANY_DOMAIN) . "\n\n"
        . "LOG_CHANNEL=stack\nLOG_LEVEL=error\n\n"
        . "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\n"
        . "DB_DATABASE=" . FAKE_DB_NAME . "\nDB_USERNAME=" . FAKE_DB_USER
        . "\nDB_PASSWORD=" . FAKE_DB_PASSWORD . "\n\n"
        . "REDIS_HOST=127.0.0.1\nREDIS_PASSWORD=null\nREDIS_PORT=6379\n\n"
        . "MAIL_MAILER=smtp\nMAIL_HOST=mail." . ($identity['fake_hostname'] ?? 'srv-01')
        . "\nMAIL_PORT=587\nMAIL_USERNAME=noreply@" . COMPANY_DOMAIN . "\n"
        . "MAIL_PASSWORD=" . FAKE_MAIL_PASSWORD . "\nMAIL_ENCRYPTION=tls\n\n"
        . "AWS_ACCESS_KEY_ID=" . FAKE_AWS_KEY_ID . "\n"
        . "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\n"
        . "AWS_DEFAULT_REGION=us-east-2\nAWS_BUCKET=" . COMPANY_SLUG . "-prod-assets\n";
}

function fake_git_config(): string
{
    return "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
        . "\tlogallrefupdates = true\n"
        . "[remote \"origin\"]\n"
        . "\turl = https://deploy:ghp_8Kx2mN9pQ4rT7yU1iO3pAsDfGhJkLzXcVbNm@git."
        . COMPANY_DOMAIN . "/web/" . COMPANY_SLUG . "-site.git\n"
        . "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        . "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
        . "[user]\n\tname = Deploy Bot\n\temail = deploy@" . COMPANY_DOMAIN . "\n";
}

function fake_wp_config_file(array $identity): string
{
    return "<?php\n/**\n * The base configuration for WordPress\n */\n\n"
        . "define( 'DB_NAME', '" . FAKE_DB_NAME . "' );\n"
        . "define( 'DB_USER', '" . FAKE_DB_USER . "' );\n"
        . "define( 'DB_PASSWORD', '" . FAKE_DB_PASSWORD . "' );\n"
        . "define( 'DB_HOST', '127.0.0.1:3306' );\n"
        . "define( 'DB_CHARSET', 'utf8mb4' );\n"
        . "define( 'DB_COLLATE', '' );\n\n"
        . "define( 'AUTH_KEY',         '" . FAKE_HONEYTOKEN_KEY . "' );\n"
        . "define( 'SECURE_AUTH_KEY',  '" . FAKE_MAIL_PASSWORD . "-secure-auth-salt' );\n"
        . "define( 'LOGGED_IN_KEY',    '" . COMPANY_SLUG . "-logged-in-2024-key-x9f2' );\n"
        . "define( 'NONCE_KEY',        '" . COMPANY_SLUG . "-nonce-2024-key-b7k1' );\n\n"
        . "\$table_prefix = 'wp_';\n\n"
        . "define( 'WP_DEBUG', false );\n"
        . "define( 'FS_METHOD', 'direct' );\n\n"
        . "/* Staging box: " . FAKE_STAGING_IP . " admin:" . FAKE_MAIL_PASSWORD . " */\n\n"
        . "if ( ! defined( 'ABSPATH' ) ) {\n"
        . "\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n\n"
        . "require_once ABSPATH . 'wp-settings.php';\n";
}

function fake_phpinfo_page(array $identity): string
{
    $hostname = $identity['fake_hostname'] ?? 'prod-web-01';
    $kernel = $identity['fake_kernel'] ?? '5.15.0-86-generic';
    $rows = [
        'System' => "Linux {$hostname} {$kernel} #1 SMP Debian x86_64",
        'Build Date' => 'Nov  2 2023 12:41:22',
        'Server API' => 'FPM/FastCGI',
        'Loaded Configuration File' => '/etc/php/' . FAKE_PHP_SERIES . '/fpm/php.ini',
        'PHP API' => '20190902',
        'Thread Safety' => 'disabled',
        'IPv6 Support' => 'enabled',
        'Registered PHP Streams' => 'https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar',
        'disable_functions' => 'no value',
        'allow_url_fopen' => 'On',
        'open_basedir' => 'no value',
        'upload_max_filesize' => '20M',
        'DB_PASSWORD' => FAKE_DB_PASSWORD,
    ];
    $body = '';
    foreach ($rows as $key => $value) {
        $body .= '<tr><td class="e">' . sb_html((string)$key) . '</td><td class="v">'
            . sb_html((string)$value) . '</td></tr>';
    }
    return '<!DOCTYPE html><html><head><title>phpinfo()</title><style>'
        . 'body{background:#fff;color:#000;font-family:sans-serif;font-size:.8em}'
        . 'table{border-collapse:collapse;width:600px;margin:0 auto;border:1px solid #666}'
        . 'td{border:1px solid #666;padding:4px 8px}'
        . '.e{background:#ccf;font-weight:bold;width:300px}.v{background:#ccc}'
        . 'h1{text-align:center;background:#99c;padding:8px;width:600px;margin:1em auto}'
        . '</style></head><body>'
        . '<h1>PHP Version ' . sb_html(FAKE_PHP_VERSION) . '</h1>'
        . '<table>' . $body . '</table></body></html>';
}

function adminer_login_page(): string
{
    return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        . '<title>Login - Adminer</title><style>'
        . 'body{font-family:Verdana,sans-serif;margin:0;background:#fff;color:#000;font-size:90%}'
        . '#content{margin:1em 0 0 2em}h1{font-size:150%;margin:0;padding:.8em 1em;'
        . 'background:#eee;border-bottom:1px solid #ccc}'
        . 'p{margin:1em 0}input{font:inherit;padding:2px 4px}'
        . 'input[type=submit]{padding:2px 12px}#lang{position:absolute;top:.5em;right:1em}'
        . '</style></head><body><h1>Adminer <span style="font-size:70%">4.8.1</span></h1>'
        . '<div id="content"><form action="" method="post"><p>'
        . 'System: <select name="auth[driver]"><option value="server">MySQL</option>'
        . '<option value="pgsql">PostgreSQL</option><option value="sqlite">SQLite</option></select><br>'
        . 'Server: <input name="auth[server]" value="localhost"><br>'
        . 'Username: <input name="auth[username]" value=""><br>'
        . 'Password: <input type="password" name="auth[password]"><br>'
        . 'Database: <input name="auth[db]" value="">'
        . '</p><p><input type="submit" value="Login">'
        . ' <label><input type="checkbox" name="auth[permanent]" value="1"> Permanent login</label>'
        . '</p></form></div></body></html>';
}

function phpmyadmin_login_page(): string
{
    return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        . '<title>phpMyAdmin</title><style>'
        . 'body{font-family:sans-serif;background:#f5f5f5;margin:0;padding:0}'
        . '.container{width:340px;margin:6em auto;background:#fff;border:1px solid #ccc;'
        . 'border-radius:4px;padding:1.5em}'
        . '.logo{text-align:center;margin-bottom:1em;color:#235a81;font-size:1.6em;font-weight:bold}'
        . 'label{display:block;margin:.6em 0 .2em}'
        . 'input[type=text],input[type=password]{width:100%;padding:6px;box-sizing:border-box;'
        . 'border:1px solid #aaa;border-radius:2px}'
        . 'input[type=submit]{margin-top:1em;width:100%;padding:8px;background:#235a81;'
        . 'color:#fff;border:0;border-radius:2px;cursor:pointer}'
        . '</style></head><body><div class="container">'
        . '<div class="logo">phpMyAdmin</div><form method="post" action="index.php">'
        . '<label for="u">Username:</label><input type="text" id="u" name="pma_username" value="root">'
        . '<label for="p">Password:</label><input type="password" id="p" name="pma_password">'
        . '<label for="s">Server Choice:</label><input type="text" id="s" name="pma_servername" value="localhost">'
        . '<input type="submit" value="Go"></form>'
        . '<p style="font-size:.8em;color:#666;margin-top:1em">phpMyAdmin 5.2.1 &mdash; '
        . 'MySQL ' . sb_html(FAKE_MYSQL_VERSION) . '</p>'
        . '</div></body></html>';
}

function render_wordpress_404(): void
{
    http_response_code(404);
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    echo '<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>Page not found &#8211; ' . sb_html(COMPANY_NAME) . '</title>'
        . '<meta name="generator" content="WordPress 6.4.3">'
        . '<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;'
        . 'max-width:700px;margin:0 auto;padding:3rem 2rem;color:#1a2744;line-height:1.6}'
        . 'h1{font-size:2rem;border-bottom:3px solid #3a5fa0;padding-bottom:.5rem}'
        . 'a{color:#3a5fa0}form{margin-top:1.5rem}'
        . 'input[type=search]{padding:.5rem;width:260px;border:1px solid #ccc}'
        . 'input[type=submit]{padding:.5rem 1rem;background:#3a5fa0;color:#fff;border:0;cursor:pointer}'
        . '</style></head><body>'
        . '<h1>Oops! That page can&rsquo;t be found.</h1>'
        . '<p>It looks like nothing was found at this location. Maybe try a search?</p>'
        . '<form role="search" method="get" action="/">'
        . '<input type="search" name="s" placeholder="Search &hellip;">'
        . '<input type="submit" value="Search"></form>'
        . '<p style="margin-top:2rem"><a href="/">&larr; Back to ' . sb_html(COMPANY_NAME) . '</a></p>'
        . '</body></html>';
}
