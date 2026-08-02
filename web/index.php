<?php
declare(strict_types=1);

/*
 * Drosera webshell emulator and crawler trap.
 *
 * Reachable only through nginx's explicit SCRIPT_FILENAME mappings:
 *   /wp-admin/admin-ajax.php  -> the c99-style webshell UI
 *   /blog/...                 -> the infinite crawler trap
 *
 * This file sits outside the document root, so it can never be requested
 * directly. See web/lib/drosera.php for the zero-trust contract this inherits:
 * nothing here executes, evaluates, connects, or touches a real path.
 */

require_once __DIR__ . '/lib/drosera.php';

[$ip, $identity] = sb_bootstrap();

$requestUri = (string)($_SERVER['REQUEST_URI'] ?? '/');
$path = parse_url($requestUri, PHP_URL_PATH) ?: '/';

log_request($ip, ['tab' => $_GET['tab'] ?? null, 'action' => $_GET['action'] ?? null]);

// Check for crash mode before any content
if (sb_is_crashed($ip)) {
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . strlen($crash_payload));
    header('Connection: close');
    // Generate malformed HTTP response
    $crash_response = "HTTP/1.1 200 OK\r\n";
    $crash_response .= "Server: Apache\r\n";
    $crash_response .= "Content-Type: text/html; charset=UTF-8\r\n";
    $crash_response .= "Content-Length: " . random_int(999999, 9999999) . "\r\n";
    $crash_response .= "\r\n";
    // Send partial content then garbage
    echo substr($crash_response, 0, random_int(10, strlen($crash_response) - 1));
    for ($i = 0; $i < random_int(100, 500); $i++) {
        echo chr(random_int(0, 255));
    }
    exit;
}

// Detect nmap in User-Agent
$ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
if (stripos($ua, 'nmap') !== false || stripos($ua, 'NSE') !== false) {
    score_event($ip, 'TOOL_NMAP', 'nmap detected in User-Agent: ' . substr($ua, 0, 100), 'nmap');
    // Check if this triggered crash mode
    if (score_event($ip, 'TOOL_NMAP')['new_score'] >= CRASH_THRESHOLD) {
        sb_activate_crash($ip, 'nmap detected (score threshold)');
        header('Content-Type: application/octet-stream');
        echo random_bytes(random_int(256, 2048));
        exit;
    }
    // Return fake nmap result
    header('Content-Type: text/plain');
    echo "Starting Nmap\r\n";
    echo "Nmap scan report for $ip\r\n";
    echo "22/tcp    open    ssh\r\n";
    echo "23/tcp    open    telnet\r\n";
    echo "80/tcp    open    http\r\n";
    echo "443/tcp   open    https\r\n";
    echo "3306/tcp  open    mysql\r\n";
    echo "445/tcp   open    microsoft-ds\r\n";
    exit;
}

if (str_starts_with($path, '/blog/') || $path === '/blog') {
    serve_crawler_trap($ip, $path);
}

// The shell hides behind a magic action parameter. A scanner that merely finds
// admin-ajax.php gets WordPress's authentic "0" for an unknown action, so the
// path does not immediately advertise itself as a webshell. Once an IP supplies
// the right value we remember it, so their later requests land straight in.
if (!webshell_unlocked($ip)) {
    score_event($ip, 'SCANNER_PATH_HIT', 'admin-ajax.php probed without action key');
    sb_cam_http($ip, sprintf('%s %s', $_SERVER['REQUEST_METHOD'] ?? 'GET',
                             substr((string)($_SERVER['REQUEST_URI'] ?? '/'), 0, 200)),
                'admin-ajax.php probed without the action key -> "0"');
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    echo '0';
    exit;
}

render_webshell($ip, $identity);
exit;

/**
 * True once this IP has presented the webshell action key, now or previously.
 */
function webshell_unlocked(string $ip): bool
{
    $redis = sb_redis();
    $key = 'hp:shell:' . sb_ip_hash($ip);

    $supplied = (string)($_REQUEST['action'] ?? '');
    if ($supplied !== '' && hash_equals(WEBSHELL_ACTION, $supplied)) {
        if ($redis->isReady()) {
            $redis->setex($key, IDENTITY_TTL, '1');
        }
        return true;
    }

    return $redis->isReady() && $redis->exists($key) > 0;
}

// ============================================================== crawler trap

/**
 * Infinite procedurally generated blog.
 *
 * Content is derived from crc32 of the slug so a crawler revisiting a URL sees
 * identical content (looks real) while always finding new URLs to follow. The
 * slug is used only as a numeric seed -- never in a path, query, or call.
 */
function serve_crawler_trap(string $ip, string $path): void
{
    $slug = trim(substr($path, strlen('/blog')), '/');
    if ($slug === '') {
        $slug = 'index';
    }
    $slug = mb_substr($slug, 0, 120);

    $redis = sb_redis();
    if ($redis->isReady()) {
        $key = 'hp:crawler:' . sb_ip_hash($ip);
        $redis->lpush($key, substr(hash('sha256', $slug), 0, 16));
        $redis->ltrim($key, 0, 49);
        $redis->expire($key, 3600);
        $visited = $redis->lrange($key, 0, 49);
        if (is_array($visited) && count(array_unique($visited)) >= 3) {
            score_event($ip, 'SCANNER_PATH_HIT', "crawler trap: {$slug}");
            // Only once they are demonstrably crawling rather than on the
            // first page, which a person could land on by accident.
            sb_cam_http($ip, 'GET ' . substr($slug, 0, 200),
                        'crawler trap, ' . count(array_unique($visited))
                        . ' generated pages followed');
        }
    }

    $seed = crc32($slug);
    $fragments = [
        'cloud migration', 'zero trust', 'incident response', 'managed services',
        'infrastructure as code', 'disaster recovery', 'compliance posture',
        'endpoint hardening', 'network segmentation', 'identity federation',
        'container orchestration', 'observability', 'cost optimisation',
        'business continuity', 'threat modelling', 'patch management',
        'backup strategy', 'capacity planning', 'vendor consolidation',
        'technical debt', 'change control', 'service levels', 'data residency',
        'edge caching', 'API gateways', 'secret rotation', 'least privilege',
        'log retention', 'asset inventory', 'configuration drift',
    ];

    $pick = static function (int $offset) use ($fragments, $seed): string {
        return $fragments[abs(($seed >> ($offset % 24)) + $offset) % count($fragments)];
    };

    $title = ucfirst($pick(1)) . ': ' . ucfirst($pick(3)) . ' for Growing Teams';
    $published = gmdate('F j, Y', 1700000000 + ($seed % 15000000));

    $paragraphs = '';
    for ($p = 0; $p < 6; $p++) {
        $sentence = '';
        for ($s = 0; $s < 5; $s++) {
            $sentence .= sprintf(
                'Effective %s depends on disciplined %s across every environment. ',
                $pick($p * 7 + $s), $pick($p * 11 + $s + 2)
            );
        }
        $paragraphs .= '<p>' . sb_html($sentence) . "</p>\n";
    }

    $links = '';
    for ($i = 1; $i <= 5; $i++) {
        $childSlug = substr(hash('sha256', $slug . '-' . $i), 0, 12)
            . '-' . str_replace(' ', '-', $pick($i * 5));
        $links .= sprintf(
            '<li><a href="/blog/%s">%s</a></li>' . "\n",
            rawurlencode($childSlug), sb_html(ucfirst($pick($i * 3)) . ' in practice')
        );
    }
    $nextSlug = substr(hash('sha256', $slug . '-next'), 0, 12);

    header('Content-Type: text/html; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    header('Link: </blog/' . $nextSlug . '>; rel="next"');

    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . sb_html($title) . ' &ndash; ' . sb_html(COMPANY_NAME) . '</title>';
    echo '<meta name="generator" content="WordPress 6.4.3">';
    echo '<link rel="next" href="/blog/' . sb_html($nextSlug) . '">';
    echo '<style>body{font-family:Georgia,serif;max-width:820px;margin:0 auto;'
        . 'padding:2rem;color:#222;line-height:1.7}header{border-bottom:3px solid #1a2744;'
        . 'padding-bottom:1rem;margin-bottom:2rem}h1{color:#1a2744}'
        . 'aside{background:#f4f6fa;padding:1rem 1.5rem;margin-top:2.5rem;border-left:4px solid #3a5fa0}'
        . 'a{color:#3a5fa0}.meta{color:#777;font-size:.9rem}</style></head><body>';
    echo '<header><a href="/"><strong>' . sb_html(COMPANY_NAME) . '</strong></a></header>';
    echo '<article><h1>' . sb_html($title) . '</h1>';
    echo '<p class="meta">Posted ' . sb_html($published) . ' by the '
        . sb_html(explode(' ', COMPANY_SHORT)[0]) . ' team</p>';
    echo $paragraphs;
    echo '</article><aside><h3>Related reading</h3><ul>' . $links . '</ul></aside>';
    echo '<p><a href="/blog/' . sb_html($nextSlug) . '">Next article &rarr;</a></p>';
    echo '</body></html>';
    exit;
}

// ================================================================== webshell

function render_webshell(string $ip, array $identity): void
{
    $tab = (string)($_GET['tab'] ?? 'cmd');
    $allowed = ['cmd', 'php', 'mysql', 'files', 'info', 'network'];
    if (!in_array($tab, $allowed, true)) {
        $tab = 'cmd';
    }

    $result = '';
    $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));

    if ($method === 'POST') {
        $result = handle_webshell_post($ip, $identity, $tab);
        $identity = get_or_create_identity($ip);
    } elseif ($tab === 'network') {
        $result = network_overview($identity);
        score_event($ip, 'NETWORK_ENUM', 'network tab opened');
        $identity = get_or_create_identity($ip);
    } elseif ($tab === 'files') {
        $result = files_listing($ip, $identity, (string)($_GET['path'] ?? $identity['fake_cwd']));
    } elseif ($tab === 'info') {
        $result = fake_phpinfo($identity);
    }

    header('Content-Type: text/html; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);

    $host = $identity['fake_hostname'] ?? 'srv-01';
    $wan = $identity['fake_wan_ip'] ?? '0.0.0.0';
    $lan = $identity['fake_lan_ip'] ?? '10.0.1.50';
    $os = $identity['fake_os'] ?? 'Ubuntu 22.04.3 LTS';
    $kernel = $identity['fake_kernel'] ?? '5.15.0-86-generic';

    ?><!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>c99shell</title>
<style>
body{background:#000;color:#0c0;font-family:'Courier New',monospace;font-size:12px;margin:0;padding:8px}
a{color:#0f0;text-decoration:none}a:hover{text-decoration:underline}
.hdr{border:1px solid #0c0;padding:6px;margin-bottom:8px;background:#001100}
.hdr td{padding:1px 8px 1px 0;color:#0c0}
.tabs{margin:8px 0}
.tabs a{border:1px solid #0c0;padding:3px 12px;margin-right:3px;display:inline-block;background:#000}
.tabs a.active{background:#003300;font-weight:bold}
pre.out{background:#001100;padding:8px;border:1px solid #030;white-space:pre-wrap;word-break:break-all;margin:8px 0;max-height:600px;overflow:auto}
input[type=text],input[type=password],textarea,select{background:#001100;color:#0c0;border:1px solid #040;font-family:inherit;font-size:12px;padding:3px}
input[type=submit],button{background:#003300;color:#0c0;border:1px solid #0c0;padding:3px 14px;font-family:inherit;cursor:pointer}
table.fs{width:100%;border-collapse:collapse}
table.fs td,table.fs th{border-bottom:1px solid #020;padding:2px 8px;text-align:left}
table.fs th{color:#0f0}
.ftr{margin-top:12px;border-top:1px solid #030;padding-top:6px;color:#080}
.w100{width:100%}
</style></head><body>

<div class="hdr"><table>
<tr><td>Hostname:</td><td><b><?= sb_html($host) ?></b></td>
    <td>OS:</td><td><?= sb_html($os) ?> (<?= sb_html($kernel) ?>)</td></tr>
<tr><td>WAN IP:</td><td><?= sb_html($wan) ?></td>
    <td>LAN IP:</td><td><?= sb_html($lan) ?></td></tr>
<tr><td>Server:</td><td><?= sb_html(FAKE_SERVER_SOFTWARE) ?></td>
    <td>PHP:</td><td><?= sb_html(FAKE_PHP_VERSION) ?> · safe_mode: <b>OFF</b></td></tr>
<tr><td>User:</td><td>www-data (33)</td>
    <td>Time:</td><td><?= sb_html(gmdate('D M j H:i:s Y')) ?> UTC</td></tr>
</table></div>

<div class="tabs">
<?php foreach (['cmd', 'php', 'mysql', 'files', 'info', 'network'] as $name): ?>
<a href="<?= sb_html(WEBSHELL_PATH) ?>?tab=<?= $name ?>"<?= $tab === $name ? ' class="active"' : '' ?>><?= $name ?></a>
<?php endforeach; ?>
</div>

<?php render_tab_form($tab, $identity); ?>

<?php if ($result !== ''): ?>
<pre class="out"><?= $result ?></pre>
<?php endif; ?>

<div class="ftr">c99shell v. 1.0 pre-release build #16 &middot; Tue Mar 13 2012 &middot; PHP <?= sb_html(FAKE_PHP_VERSION) ?></div>
</body></html>
<?php
}

function render_tab_form(string $tab, array $identity): void
{
    $action = sb_html(WEBSHELL_PATH) . '?tab=' . $tab;
    switch ($tab) {
        case 'cmd':
            echo '<form method="post" action="' . $action . '">'
                . '<b>Execute command:</b><br><input type="text" name="cmd" class="w100" '
                . 'autofocus autocomplete="off" value="' . sb_html((string)($_POST['cmd'] ?? '')) . '"> '
                . '<input type="submit" value="Execute"></form>';
            break;

        case 'php':
            echo '<form method="post" action="' . $action . '">'
                . '<b>Execute PHP code:</b><br>'
                . '<textarea name="code" rows="10" class="w100">'
                . sb_html((string)($_POST['code'] ?? '')) . '</textarea><br>'
                . '<input type="submit" value="Eval"></form>';
            break;

        case 'mysql':
            echo '<form method="post" action="' . $action . '">'
                . '<b>MySQL console</b><br>'
                . 'Host: <input type="text" name="host" value="127.0.0.1"> '
                . 'User: <input type="text" name="user" value="' . sb_html(FAKE_DB_USER) . '"> '
                . 'Pass: <input type="text" name="pass" value="' . sb_html(FAKE_DB_PASSWORD) . '"> '
                . 'DB: <input type="text" name="db" value="' . sb_html(FAKE_DB_NAME) . '"><br><br>'
                . '<textarea name="sql" rows="6" class="w100">'
                . sb_html((string)($_POST['sql'] ?? 'SHOW TABLES;')) . '</textarea><br>'
                . '<input type="submit" value="Run SQL"></form>';
            break;

        case 'files':
            $cwd = (string)($_GET['path'] ?? ($identity['fake_cwd'] ?? '/var/www/html'));
            echo '<form method="get" action="' . sb_html(WEBSHELL_PATH) . '">'
                . '<input type="hidden" name="tab" value="files">'
                . '<b>Path:</b> <input type="text" name="path" value="' . sb_html($cwd) . '" size="60"> '
                . '<input type="submit" value="Go"></form>'
                . '<form method="post" action="' . $action . '" enctype="multipart/form-data">'
                . '<b>Upload file:</b> <input type="file" name="file"> '
                . '<input type="submit" value="Upload"><br>'
                . '<span style="color:#080">Supported types: php, php5, phtml, phar, jpg, png, zip '
                . '(no restrictions enforced)</span></form>';
            break;

        case 'network':
            echo '<form method="post" action="' . $action . '">'
                . '<input type="hidden" name="scan" value="1">'
                . '<input type="submit" value="Scan local network"></form>';
            break;
    }
}

function handle_webshell_post(string $ip, array $identity, string $tab): string
{
    // Each branch records the exchange to the session camera before escaping it
    // for display. The recorded command line is a readable stand-in for what the
    // attacker did in that tab -- it is written as text and never executed.
    switch ($tab) {
        case 'cmd':
            $command = mb_substr((string)($_POST['cmd'] ?? ''), 0, 4096);
            if ($command === '') {
                return '';
            }
            $output = simulate_command($ip, $identity, $command);
            sb_cam_record($ip, $command, $output);
            return sb_html($output);

        case 'php':
            $code = mb_substr((string)($_POST['code'] ?? ''), 0, 8192);
            $output = simulate_php($ip, $code);
            sb_cam_record($ip, "php -r '" . $code . "'", $output);
            return sb_html($output);

        case 'mysql':
            $sql = mb_substr((string)($_POST['sql'] ?? ''), 0, 8192);
            $output = simulate_sql($ip, $sql);
            sb_cam_record($ip, 'mysql -e "' . $sql . '"', $output);
            return sb_html($output);

        case 'files':
            $output = simulate_upload($ip, $identity);
            sb_cam_record($ip, '# file upload', $output);
            return sb_html($output);

        case 'network':
            score_event($ip, 'NETWORK_ENUM', 'local network scan');
            $output = fake_nmap_scan($identity);
            sb_cam_record($ip, 'nmap -sn ' . ($identity['fake_lan_ip'] ?? '10.0.1.0') . '/24',
                          $output);
            return sb_html($output);
    }
    return '';
}

// ------------------------------------------------------------- cmd simulation

function simulate_command(string $ip, array $identity, string $command): string
{
    score_event($ip, 'WEBSHELL_CMD', $command);

    $trimmed = trim($command);
    $tokens = preg_split('/\s+/', $trimmed) ?: [];
    $verb = strtolower($tokens[0] ?? '');
    $args = array_slice($tokens, 1);
    $hostname = $identity['fake_hostname'] ?? 'srv-01';

    // Reverse shell / download-and-run attempts get realistic timeout behaviour.
    if (preg_match('#(/dev/tcp/|\bnc\s+-[a-z]*e|\bncat\b|\bsocat\b|bash\s+-i|sh\s+-i'
        . '|mkfifo|python[23]?\s+-c.*socket|perl\s+-e.*socket|php\s+-r.*fsockopen'
        . '|\|\s*(ba)?sh\b|base64\s+-d)#i', $trimmed)) {
        score_event($ip, 'REVERSE_SHELL', $trimmed);
        activate_tarpit($ip, 'Reverse shell payload in webshell');
        usleep(3000000);
        $host = '127.0.0.1';
        $port = '4444';
        if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+\.[a-z]{2,})[\s:\/]+(\d{2,5})/i',
                       $trimmed, $m)) {
            $host = $m[1];
            $port = $m[2];
        }
        return "bash: connect to host {$host} port {$port}: Connection timed out";
    }

    // Running something they believe they dropped: `chmod +x x && ./x`, or bare `./x`.
    if (preg_match('#(?:^|&&|;|\|)\s*(\./[\w.\-]+)#', $trimmed, $m)) {
        score_event($ip, 'REVERSE_SHELL', $trimmed);
        activate_tarpit($ip, 'Execution of a dropped file attempted');
        usleep(500000);
        return "bash: {$m[1]}: cannot execute binary file: Exec format error";
    }

    switch ($verb) {
        case 'ls': case 'dir':
            score_event($ip, 'RECON_LS', $trimmed);
            return fake_ls($identity, $args);

        case 'pwd':
            return (string)($identity['fake_cwd'] ?? '/var/www/html');

        case 'id':
            return 'uid=33(www-data) gid=33(www-data) groups=33(www-data)';

        case 'whoami':
            return 'www-data';

        case 'hostname':
            return $hostname;

        case 'uname':
            if (in_array('-r', $args, true)) {
                return (string)($identity['fake_kernel'] ?? '5.15.0-86-generic');
            }
            return 'Linux ' . $hostname . ' ' . ($identity['fake_kernel'] ?? '5.15.0-86-generic')
                . ' #1 SMP Debian x86_64 x86_64 x86_64 GNU/Linux';

        case 'cat': case 'head': case 'tail': case 'less': case 'more':
            return fake_cat($ip, $identity, $args);

        case 'ps': case 'top':
            score_event($ip, 'PROCESS_ENUM', $trimmed);
            usleep(150000);
            return fake_ps();

        case 'netstat': case 'ss':
            score_event($ip, 'NETWORK_ENUM', $trimmed);
            usleep(150000);
            return fake_netstat($identity);

        case 'ifconfig':
            score_event($ip, 'NETWORK_ENUM', $trimmed);
            return fake_ifconfig($identity);

        case 'ip':
            score_event($ip, 'NETWORK_ENUM', $trimmed);
            return ($args[0] ?? '') === 'r' || str_starts_with($args[0] ?? '', 'r')
                ? "default via 10.0.1.1 dev eth0 proto static\n10.0.1.0/24 dev eth0 proto kernel scope link src "
                    . ($identity['fake_lan_ip'] ?? '10.0.1.50')
                : fake_ifconfig($identity);

        case 'arp':
            score_event($ip, 'NETWORK_ENUM', $trimmed);
            return "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
                . "10.0.1.1                 ether   00:1b:21:3c:4d:5e   C                     eth0\n"
                . str_pad(FAKE_LAST_LOGIN_FROM, 25) . "ether   00:50:56:9a:11:c2   C                     eth0\n"
                . "10.0.1.23                ether   00:50:56:9a:44:71   C                     eth0";

        case 'nmap': case 'masscan': case 'zmap': case 'rustscan':
            score_event($ip, 'NETWORK_ENUM', $trimmed);
            usleep(600000);
            return fake_scanback($ip, $identity);

        case 'docker': case 'kubectl':
            score_event($ip, 'DOCKER_K8S_ENUM', $trimmed);
            usleep(150000);
            return "bash: {$verb}: command not found";

        case 'history':
            return fake_history($identity);

        case 'crontab':
            return "# m h  dom mon dow   command\n"
                . "*/5 * * * * /usr/bin/php /opt/monitoring/check.php > /dev/null 2>&1\n"
                . "0 2 * * * /usr/local/bin/backup.sh > /var/log/backup.log 2>&1\n"
                . "30 3 * * 0 apt-get -qq update && apt-get -qq -y upgrade > /dev/null 2>&1";

        case 'systemctl': case 'service':
            usleep(150000);
            return fake_systemctl($args[1] ?? $args[0] ?? 'nginx');

        case 'journalctl':
            usleep(150000);
            return fake_journal($hostname);

        case 'lsof':
            score_event($ip, 'NETWORK_ENUM', $trimmed);
            usleep(150000);
            return "COMMAND   PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
                . "nginx     721     root    6u  IPv4  17033      0t0  TCP *:http (LISTEN)\n"
                . "mysqld    934    mysql   32u  IPv4  17944      0t0  TCP localhost:mysql (LISTEN)\n"
                . "php-fpm   810 www-data    9u  IPv4  18220      0t0  TCP localhost:9000 (LISTEN)";

        case 'strace': case 'ltrace':
            usleep(3000000);
            $target = $args[0] ?? 'program';
            return "execve(\"/usr/bin/{$target}\", [\"{$target}\"], 0x7ffd1a2b3c40 /* 23 vars */) = -1 "
                . "ENOENT (No such file or directory)\nstrace: Can't stat '{$target}': "
                . "No such file or directory\n+++ exited with 1 +++";

        case 'gcc': case 'cc': case 'g++':
            usleep(2000000);
            $file = '';
            foreach ($args as $arg) {
                if (!str_starts_with($arg, '-')) { $file = $arg; break; }
            }
            $file = $file ?: 'a.c';
            return "gcc: error: {$file}: No such file or directory\n"
                . "gcc: fatal error: no input files\ncompilation terminated.";

        case 'make':
            usleep(2000000);
            return 'make: *** No targets specified and no makefile found.  Stop.';

        case 'git':
            if (($args[0] ?? '') === 'clone') {
                usleep(3000000);
                $url = $args[1] ?? 'https://github.com/example/repo.git';
                $host = explode('/', preg_replace('#^\w+://#', '', $url))[0];
                $name = basename(str_replace('.git', '', $url));
                return "Cloning into '{$name}'...\nfatal: unable to connect to {$host}:\n"
                    . "{$host}: Connection refused";
            }
            return 'usage: git [--version] [--help] [-C <path>] <command> [<args>]';

        case 'apt': case 'apt-get': case 'yum': case 'dnf':
            usleep(500000);
            return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open "
                . "(13: Permission denied)\nE: Unable to acquire the dpkg frontend lock "
                . "(/var/lib/dpkg/lock-frontend), are you root?";

        case 'pip': case 'pip3':
            usleep(500000);
            $pkg = $args[1] ?? 'package';
            return "Defaulting to user installation because normal site-packages is not writeable\n"
                . "Collecting {$pkg}\n  Downloading {$pkg}-2.1.0-py3-none-any.whl (48 kB)\n"
                . "Installing collected packages: {$pkg}\nSuccessfully installed {$pkg}-2.1.0";

        case 'wget':
            usleep(3000000);
            $url = $args[0] ?? 'http://example.com';
            $host = explode('/', preg_replace('#^\w+://#', '', $url))[0];
            return '--' . gmdate('Y-m-d H:i:s') . "--  {$url}\nResolving {$host} ({$host})... "
                . "failed: Temporary failure in name resolution.\n"
                . "wget: unable to resolve host address '{$host}'";

        case 'curl':
            usleep(3000000);
            $url = $args[0] ?? 'http://example.com';
            $host = explode('/', preg_replace('#^\w+://#', '', $url))[0];
            return "curl: (6) Could not resolve host: {$host}";

        case 'df':
            return "Filesystem      Size  Used Avail Use% Mounted on\n"
                . "udev            1.9G     0  1.9G   0% /dev\n"
                . "/dev/vda1        79G   31G   45G  41% /\n"
                . "tmpfs           2.0G     0  2.0G   0% /dev/shm";

        case 'free':
            return "               total        used        free      shared  buff/cache   available\n"
                . "Mem:            3936        1482         241          38        2212        2158\n"
                . "Swap:           2047         118        1929";

        case 'uptime':
            return ' ' . gmdate('H:i:s') . ' up 47 days,  3:19,  1 user,  load average: 0.28, 0.34, 0.31';

        case 'w': case 'who':
            return "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                . 'root     pts/0    ' . str_pad(FAKE_LAST_LOGIN_FROM, 17)
                . "08:14    0.00s  0.04s  0.00s -bash";

        case 'env': case 'printenv':
            return "SHELL=/bin/bash\nPWD=" . ($identity['fake_cwd'] ?? '/var/www/html')
                . "\nUSER=www-data\nHOME=/var/www\nLANG=en_US.UTF-8\n"
                . "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                . 'DB_PASSWORD=' . FAKE_DB_PASSWORD;

        case 'echo':
            return implode(' ', $args);

        case 'find': case 'locate':
            score_event($ip, 'RECON_LS', $trimmed);
            usleep(1500000);
            return "/var/www/html/wp-config.php\n/var/www/html/index.php\n"
                . "/var/www/html/wp-content/uploads/2024/01/strategic-plan-2024.pdf\n"
                . "find: '/root': Permission denied";

        case 'su': case 'sudo':
            usleep(2000000);
            score_event($ip, 'CREDENTIAL_ATTEMPT', $trimmed);
            return $verb === 'su'
                ? 'su: Authentication failure'
                : "[sudo] password for www-data: \nsudo: 1 incorrect password attempt";

        case 'chmod': case 'chown': case 'touch': case 'mkdir': case 'export': case 'cd':
            return '';

        case 'rm': case 'rmdir':
            $target = $args[0] ?? '';
            return $target === '' ? '' : "rm: cannot remove '{$target}': Permission denied";

        default:
            return "bash: {$verb}: command not found";
    }
}

function fake_ls(array $identity, array $args): string
{
    $long = false;
    $all = false;
    $path = (string)($identity['fake_cwd'] ?? '/var/www/html');
    foreach ($args as $arg) {
        if (str_starts_with($arg, '-')) {
            $long = $long || str_contains($arg, 'l');
            $all = $all || str_contains($arg, 'a');
        } else {
            $path = $arg;
        }
    }

    $node = fs_lookup($identity, $path);
    if ($node === null) {
        return "ls: cannot access '{$path}': No such file or directory";
    }
    if (($node['type'] ?? '') !== 'dir') {
        return $path;
    }

    $children = $node['children'] ?? [];
    $names = array_keys($children);
    sort($names);
    if (!$all) {
        $names = array_values(array_filter($names, static fn($n) => !str_starts_with($n, '.')));
    }
    if (!$long) {
        return implode('  ', $names);
    }

    $stamp = gmdate('M j H:i');
    $lines = ['total ' . max(4, count($names) * 4)];
    foreach ($names as $name) {
        $child = $children[$name];
        $isDir = ($child['type'] ?? '') === 'dir';
        $mode = $child['mode'] ?? ($isDir ? 'drwxr-xr-x' : '-rw-r--r--');
        $size = $isDir ? 4096 : (int)($child['size'] ?? 0);
        $lines[] = sprintf('%s  %2d www-data www-data %10d %s %s',
            $mode, $isDir ? 2 : 1, $size, $stamp, $name);
    }
    return implode("\n", $lines);
}

function fake_cat(string $ip, array $identity, array $args): string
{
    $out = [];
    foreach ($args as $arg) {
        if (str_starts_with($arg, '-')) {
            continue;
        }
        $resolved = fs_resolve($identity, $arg);

        if ($resolved === '/etc/passwd') {
            score_event($ip, 'READ_PASSWD', $resolved);
            $out[] = fake_passwd($identity);
            continue;
        }
        if ($resolved === '/etc/shadow') {
            score_event($ip, 'READ_SHADOW', $resolved);
            $out[] = "cat: /etc/shadow: Permission denied";
            continue;
        }
        if (str_ends_with($resolved, 'wp-config.php')) {
            $out[] = fake_wp_config();
            continue;
        }
        if ($resolved === '/etc/hostname') {
            $out[] = (string)($identity['fake_hostname'] ?? 'srv-01');
            continue;
        }
        if ($resolved === '/etc/os-release') {
            $os = $identity['fake_os'] ?? 'Ubuntu 22.04.3 LTS';
            $out[] = "PRETTY_NAME=\"{$os}\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n"
                . "ID=ubuntu\nID_LIKE=debian";
            continue;
        }

        $node = fs_lookup($identity, $resolved);
        if ($node === null) {
            $out[] = "cat: {$arg}: No such file or directory";
        } elseif (($node['type'] ?? '') === 'dir') {
            $out[] = "cat: {$arg}: Is a directory";
        } else {
            $out[] = "cat: {$arg}: Permission denied";
        }
    }
    return implode("\n", $out);
}

function fake_passwd(array $identity): string
{
    $lines = [
        'root:x:0:0:root:/root:/bin/bash',
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
        'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
        'sshd:x:110:65534::/run/sshd:/usr/sbin/nologin',
        'mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false',
    ];
    foreach (($identity['fake_users'] ?? []) as $user) {
        if (in_array($user['username'] ?? '', ['root', 'www-data'], true)) {
            continue;
        }
        $lines[] = sprintf('%s:x:%d:%d:%s,,,:%s:%s',
            $user['username'], $user['uid'], $user['gid'],
            ucfirst((string)$user['username']), $user['home'], $user['shell']);
    }
    return implode("\n", $lines);
}

function fake_wp_config(): string
{
    return "<?php\ndefine( 'DB_NAME', '" . FAKE_DB_NAME . "' );\n"
        . "define( 'DB_USER', '" . FAKE_DB_USER . "' );\n"
        . "define( 'DB_PASSWORD', '" . FAKE_DB_PASSWORD . "' );\n"
        . "define( 'DB_HOST', '127.0.0.1:3306' );\ndefine( 'DB_CHARSET', 'utf8mb4' );\n"
        . "define( 'AUTH_KEY',  '" . FAKE_HONEYTOKEN_KEY . "' );\n"
        . "\$table_prefix = 'wp_';\ndefine( 'WP_DEBUG', false );\n"
        . "require_once ABSPATH . 'wp-settings.php';";
}

function fake_ps(): string
{
    return "  PID TTY      STAT   TIME COMMAND\n"
        . "    1 ?        Ss     0:04 /sbin/init\n"
        . "  689 ?        Ss     0:00 /usr/sbin/sshd -D\n"
        . "  721 ?        Ss     2:17 nginx: master process /usr/sbin/nginx\n"
        . "  722 ?        S      0:48 nginx: worker process\n"
        . "  810 ?        Ss     1:52 php-fpm: master process\n"
        . "  811 ?        S      0:31 php-fpm: pool www\n"
        . "  934 ?        Ssl    8:22 /usr/sbin/mysqld\n"
        . " 1204 ?        Ss     0:00 /usr/sbin/cron -f";
}

function fake_netstat(array $identity): string
{
    $lan = $identity['fake_lan_ip'] ?? '10.0.1.50';
    return "Active Internet connections (servers and established)\n"
        . "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        . "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        . "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        . "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
        . "tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN\n"
        . "tcp        0      0 {$lan}:22          " . FAKE_LAST_LOGIN_FROM . ":51442          ESTABLISHED\n"
        . "tcp6       0      0 :::443                  :::*                    LISTEN";
}

function fake_ifconfig(array $identity): string
{
    $lan = $identity['fake_lan_ip'] ?? '10.0.1.50';
    $mac = $identity['fake_mac'] ?? '02:42:ac:11:00:02';
    return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        . "        inet {$lan}  netmask 255.255.255.0  broadcast 10.0.1.255\n"
        . "        ether {$mac}  txqueuelen 1000  (Ethernet)\n"
        . "        RX packets 8842193  bytes 4821094412 (4.8 GB)\n"
        . "        TX packets 6120847  bytes 1204918822 (1.2 GB)\n\n"
        . "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        . "        inet 127.0.0.1  netmask 255.0.0.0";
}

function fake_history(array $identity): string
{
    // Same list the SSH fake shell prints. Two halves of one machine.
    $seeded = (array)sb_persona('seeded_history');
    foreach (($identity['session_history'] ?? []) as $event) {
        if (($event['event_type'] ?? '') === 'WEBSHELL_CMD' && !empty($event['payload'])) {
            $seeded[] = (string)$event['payload'];
        }
    }
    $recent = array_slice($seeded, -20);
    $out = [];
    foreach ($recent as $i => $line) {
        $out[] = sprintf('%5d  %s', $i + 1, $line);
    }
    return implode("\n", $out);
}

function fake_systemctl(string $unit): string
{
    $unit = preg_replace('/\.service$/', '', $unit) ?? 'nginx';
    $known = [
        'nginx' => [721, '2.1M', 'nginx: master process /usr/sbin/nginx -g daemon on;',
                    'A high performance web server and a reverse proxy server'],
        'mysql' => [934, '412.8M', '/usr/sbin/mysqld', 'MySQL Community Server'],
        'ssh'   => [689, '5.2M', '/usr/sbin/sshd -D', 'OpenBSD Secure Shell server'],
    ];
    if (!isset($known[$unit])) {
        return "Unit {$unit}.service could not be found.";
    }
    [$pid, $mem, $exe, $desc] = $known[$unit];
    return "● {$unit}.service - {$desc}\n"
        . "     Loaded: loaded (/lib/systemd/system/{$unit}.service; enabled; vendor preset: enabled)\n"
        . "     Active: active (running) since Mon 2023-11-27 04:51:12 UTC; 1 month 18 days ago\n"
        . "   Main PID: {$pid} ({$unit})\n      Tasks: 3 (limit: 4632)\n     Memory: {$mem}\n"
        . "        CPU: 14min 22.418s\n     CGroup: /system.slice/{$unit}.service\n"
        . "             └─{$pid} {$exe}\n\n"
        . "Warning: some journal files were not opened due to insufficient permissions.";
}

function fake_journal(string $hostname): string
{
    $stamp = gmdate('M d H:i:s');
    $admin = FAKE_LAST_LOGIN_FROM;
    return "{$stamp} {$hostname} nginx[721]: {$admin} - - \"GET /wp-admin/ HTTP/1.1\" 200 4821\n"
        . "{$stamp} {$hostname} php-fpm[810]: [pool www] child 811 said into stderr: \"NOTICE: cache warm\"\n"
        . "{$stamp} {$hostname} mysqld[934]: [Note] InnoDB: Buffer pool(s) load completed\n"
        . "{$stamp} {$hostname} cron[1204]: (root) CMD (/usr/bin/php /opt/monitoring/check.php)\n"
        . "{$stamp} {$hostname} sshd[689]: Accepted publickey for root from {$admin} port 51442 ssh2";
}

// -------------------------------------------------------------- php simulation

function simulate_php(string $ip, string $code): string
{
    if (trim($code) === '') {
        return '';
    }
    score_event($ip, 'PHP_EVAL_ATTEMPT', $code);
    activate_tarpit($ip, 'PHP eval attempted in webshell');

    $dangerous = '/\b(exec|system|shell_exec|passthru|proc_open|popen|eval|assert'
        . '|create_function|include|require|file_get_contents|file_put_contents'
        . '|curl_exec|fsockopen|pcntl_exec|preg_replace\s*\(.*\/e)\b/i';
    if (preg_match($dangerous, $code)) {
        score_event($ip, 'REVERSE_SHELL', $code);
    }

    $output = '1';
    if (preg_match('/\b(?:echo|print)\s+([\'"])(.*?)\1/s', $code, $m)) {
        $output = $m[2];
    } elseif (stripos($code, 'phpinfo') !== false) {
        $output = "phpinfo()\nPHP Version => " . FAKE_PHP_VERSION . "\n"
            . "System => Linux prod-web-01 5.15.0-86-generic x86_64\n"
            . "Server API => FPM/FastCGI\n"
            . "Loaded Configuration File => /etc/php/7.4/fpm/php.ini\n"
            . "disable_functions => no value\nsafe_mode => Off\n"
            . "allow_url_fopen => On\nallow_url_include => Off";
    } elseif (preg_match('/\b(fsockopen|stream_socket_client)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*(\d+)/i',
                         $code, $m)) {
        $output = "Warning: {$m[1]}(): unable to connect to {$m[2]}:{$m[3]} "
            . "(Connection timed out) in /var/www/html/index.php on line 1\n"
            . "php_network_getaddresses: getaddrinfo failed: Name or service not known";
    } elseif (preg_match('/\bfile_put_contents\s*\(/i', $code)) {
        $output = (string)(random_int(0, 1) ? 21 : 84);
    } elseif (preg_match('/\bmail\s*\(/i', $code)) {
        $output = '';
    } elseif (preg_match('/base64_decode/i', $code)) {
        $output = '';
    }

    return $output . "\n\nExecution time: 0.000" . random_int(2, 9)
        . " seconds · Memory: 2.1 MB";
}

// ------------------------------------------------------------- sql simulation

function simulate_sql(string $ip, string $sql): string
{
    $sql = trim($sql);
    if ($sql === '') {
        return '';
    }
    $low = strtolower(rtrim($sql, "; \t\n"));
    $header = "Connected to " . (get_or_create_identity($ip)['fake_hostname'] ?? 'prod-db-01')
        . " (" . FAKE_MYSQL_VERSION . ") as " . FAKE_DB_USER
        . ". Database: " . FAKE_DB_NAME . ".\n\n";

    if (preg_match('/\binto\s+(?:dump|out)file\b/i', $low)) {
        score_event($ip, 'SQLI_OOB', $sql);
        score_event($ip, 'FILE_UPLOAD', $sql);
        activate_tarpit($ip, 'SELECT INTO OUTFILE');
        if (preg_match('/[\'"]([^\'"]+)[\'"]\s*$/', $sql, $m)) {
            fs_add_file($ip, $m[1], 128);
        }
        return $header . 'ERROR 1290 (HY000): The MySQL server is running with the '
            . '--secure-file-priv option so it cannot execute this statement';
    }
    if (preg_match('/\bload_file\s*\(|\bload\s+data\b/i', $low)) {
        score_event($ip, 'SQLI_OOB', $sql);
        return $header . 'ERROR 1290 (HY000): The MySQL server is running with the '
            . '--secure-file-priv option so it cannot execute this statement';
    }
    if (preg_match('/\bxp_cmdshell\b/i', $low)) {
        score_event($ip, 'SQLI_OOB', $sql);
        return $header . 'ERROR 1305 (42000): PROCEDURE ' . FAKE_DB_NAME
            . '.xp_cmdshell does not exist';
    }
    if (preg_match('/\b(?:sleep|benchmark)\s*\(\s*(\d+)/i', $low, $m)) {
        score_event($ip, 'SQLI_UNION_BLIND', $sql);
        activate_tarpit($ip, 'Time-based blind SQLi');
        sleep(min((int)$m[1], 10));
        return $header . sql_table(['SLEEP(' . $m[1] . ')'], [['0']]);
    }
    if (preg_match('/\bunion\b.{0,80}?\bselect\b/is', $low)) {
        score_event($ip, 'SQLI_UNION_BLIND', $sql);
        activate_tarpit($ip, 'UNION SQLi');
    } elseif (preg_match('/(\bor\b|\band\b)\s+\d+\s*=\s*\d+|\'\s*or\s*\'/i', $low)) {
        score_event($ip, 'SQLI_BASIC', $sql);
    }

    if (str_starts_with($low, 'show databases')) {
        return $header . sql_table(['Database'],
            [['information_schema'], ['mysql'], ['performance_schema'], ['sys'], [FAKE_DB_NAME]]);
    }
    if (str_starts_with($low, 'show tables')) {
        $tables = ['wp_commentmeta', 'wp_comments', 'wp_links', 'wp_options', 'wp_postmeta',
                   'wp_posts', 'wp_term_relationships', 'wp_term_taxonomy', 'wp_termmeta',
                   'wp_terms', 'wp_usermeta', 'wp_users'];
        return $header . sql_table(['Tables_in_' . FAKE_DB_NAME],
            array_map(static fn($t) => [$t], $tables));
    }
    if (str_starts_with($low, 'show grants')) {
        return $header . sql_table(['Grants for ' . FAKE_DB_USER . '@localhost'],
            [["GRANT ALL PRIVILEGES ON `" . FAKE_DB_NAME . "`.* TO '"
              . FAKE_DB_USER . "'@'localhost'"]]);
    }
    if (str_starts_with($low, 'grant ')) {
        return $header . 'Query OK, 0 rows affected (0.00 sec)';
    }
    if (str_contains($low, 'wp_users')) {
        score_event($ip, 'SQLI_BASIC', $sql);
        // The staff username comes from the same pool the SSH honeypot uses, so
        // a name harvested here is one that "exists" on the rest of the machine.
        $staff = (array)sb_persona('user_pool');
        $staffName = (string)($staff[0][0] ?? 'jmarsh');
        return $header . sql_table(['ID', 'user_login', 'user_pass', 'user_email'], [
            ['1', 'admin', '$P$BqZ7vK2nR8xLmYcD4wF6tG9hJ1sA0e/', 'admin@' . COMPANY_DOMAIN],
            ['2', $staffName, '$P$B4kL9mN2pQ7rS5tU8vW1xY3zA6bC0d.', $staffName . '@' . COMPANY_DOMAIN],
            ['3', 'editor', '$P$BvX2cV5bN8mQ1wE4rT7yU0iO3pA6sD/', 'editor@' . COMPANY_DOMAIN],
        ]);
    }
    if (str_contains($low, 'version()') || str_contains($low, '@@version')) {
        return $header . sql_table(['version()'], [[FAKE_MYSQL_VERSION]]);
    }
    if (str_contains($low, 'user()')) {
        return $header . sql_table(['user()'], [[FAKE_DB_USER . '@localhost']]);
    }
    if (str_contains($low, 'database()')) {
        return $header . sql_table(['database()'], [[FAKE_DB_NAME]]);
    }
    if (str_starts_with($low, 'select')) {
        return $header . sql_table(['result'], [['1']]);
    }
    if (preg_match('/^(insert|update|delete|create|drop|alter)\b/', $low)) {
        return $header . 'Query OK, 1 row affected (0.00 sec)';
    }

    return $header . "ERROR 1064 (42000): You have an error in your SQL syntax; check the "
        . "manual that corresponds to your MySQL server version for the right syntax to use near '"
        . mb_substr($sql, 0, 40) . "' at line 1";
}

function sql_table(array $headers, array $rows): string
{
    $widths = [];
    foreach ($headers as $i => $header) {
        $widths[$i] = mb_strlen((string)$header);
    }
    foreach ($rows as $row) {
        foreach ($row as $i => $cell) {
            $widths[$i] = max($widths[$i] ?? 0, mb_strlen((string)$cell));
        }
    }
    $divider = '+';
    foreach ($widths as $width) {
        $divider .= str_repeat('-', $width + 2) . '+';
    }

    $out = [$divider];
    $line = '|';
    foreach ($headers as $i => $header) {
        $line .= ' ' . str_pad((string)$header, $widths[$i]) . ' |';
    }
    $out[] = $line;
    $out[] = $divider;
    foreach ($rows as $row) {
        $line = '|';
        foreach ($row as $i => $cell) {
            $line .= ' ' . str_pad((string)$cell, $widths[$i]) . ' |';
        }
        $out[] = $line;
    }
    $out[] = $divider;
    $out[] = count($rows) . ' row' . (count($rows) === 1 ? '' : 's') . ' in set (0.00 sec)';
    return implode("\n", $out);
}

// ------------------------------------------------------------- fake filesystem

function fs_resolve(array $identity, string $path): string
{
    $path = trim($path);
    if ($path === '' ) {
        return (string)($identity['fake_cwd'] ?? '/var/www/html');
    }
    if (!str_starts_with($path, '/')) {
        $path = rtrim((string)($identity['fake_cwd'] ?? '/var/www/html'), '/') . '/' . $path;
    }
    $parts = [];
    foreach (explode('/', $path) as $segment) {
        if ($segment === '' || $segment === '.') {
            continue;
        }
        if ($segment === '..') {
            array_pop($parts);
            continue;
        }
        $parts[] = $segment;
    }
    return '/' . implode('/', $parts);
}

function fs_lookup(array $identity, string $path): ?array
{
    $node = $identity['fake_filesystem'] ?? [];
    $resolved = fs_resolve($identity, $path);
    if ($resolved === '/') {
        return is_array($node) ? $node : null;
    }
    foreach (explode('/', trim($resolved, '/')) as $segment) {
        if (($node['type'] ?? '') !== 'dir') {
            return null;
        }
        $children = $node['children'] ?? [];
        if (!isset($children[$segment])) {
            return null;
        }
        $node = $children[$segment];
    }
    return is_array($node) ? $node : null;
}

/** Insert a fabricated file node so the attacker "finds" what they think they wrote. */
function fs_add_file(string $ip, string $path, int $size): void
{
    $identity = get_or_create_identity($ip);
    $resolved = fs_resolve($identity, $path);
    $segments = array_values(array_filter(explode('/', $resolved), static fn($s) => $s !== ''));
    if ($segments === []) {
        return;
    }
    $filename = array_pop($segments);

    $tree = $identity['fake_filesystem'] ?? sb_initial_filesystem();
    $cursor =& $tree;
    foreach ($segments as $segment) {
        if (($cursor['type'] ?? '') !== 'dir') {
            return;
        }
        if (!isset($cursor['children'][$segment])) {
            $cursor['children'][$segment] = sb_dir();
        }
        $cursor =& $cursor['children'][$segment];
    }
    if (($cursor['type'] ?? '') === 'dir') {
        $cursor['children'][$filename] = sb_file($size);
    }
    unset($cursor);

    update_identity($ip, ['fake_filesystem' => $tree]);
}

function files_listing(string $ip, array $identity, string $path): string
{
    score_event($ip, 'RECON_LS', "files tab: {$path}");
    $identity = get_or_create_identity($ip);

    $resolved = fs_resolve($identity, $path);
    $node = fs_lookup($identity, $resolved);
    if ($node === null) {
        return sb_html("Cannot open directory: {$resolved} (No such file or directory)");
    }
    if (($node['type'] ?? '') !== 'dir') {
        $size = (int)($node['size'] ?? 0);

        // The planted "sensitive document" is bait. Reading it starts the
        // download drip rather than returning anything.
        if (str_ends_with($resolved, 'strategic-plan-2024.pdf')) {
            score_event($ip, 'RECON_LS', "sensitive document accessed: {$resolved}");
            activate_tarpit($ip, 'Planted document download');
            run_tarpit($ip, 'Fake document download drip');
        }

        if (preg_match('/\.(png|jpe?g|gif|zip|gz|pdf|bin|so|o)$/i', $resolved)) {
            return sb_html("[Binary file - {$size} bytes - cannot display]");
        }
        if (str_ends_with($resolved, 'wp-config.php')) {
            return sb_html(fake_wp_config());
        }
        return sb_html("Permission denied reading {$resolved}");
    }

    $children = $node['children'] ?? [];
    ksort($children);
    $stamp = gmdate('Y-m-d H:i');
    $parent = dirname($resolved);

    $rows = sprintf(
        '<tr><td>drwxr-xr-x</td><td>2</td><td>root</td><td>root</td><td>4096</td>'
        . '<td>%s</td><td><a href="%s?tab=files&amp;path=%s">..</a></td></tr>',
        $stamp, sb_html(WEBSHELL_PATH), rawurlencode($parent)
    );
    foreach ($children as $name => $child) {
        $isDir = ($child['type'] ?? '') === 'dir';
        $mode = $child['mode'] ?? ($isDir ? 'drwxr-xr-x' : '-rw-r--r--');
        $size = $isDir ? 4096 : (int)($child['size'] ?? 0);
        $target = rtrim($resolved, '/') . '/' . $name;
        $rows .= sprintf(
            '<tr><td>%s</td><td>%d</td><td>www-data</td><td>www-data</td><td>%d</td>'
            . '<td>%s</td><td><a href="%s?tab=files&amp;path=%s">%s</a></td></tr>',
            sb_html($mode), $isDir ? 2 : 1, $size, $stamp,
            sb_html(WEBSHELL_PATH), rawurlencode($target), sb_html($name)
        );
    }

    return '</pre><b>' . sb_html($resolved) . '</b>'
        . '<table class="fs"><tr><th>Perms</th><th>Links</th><th>User</th><th>Group</th>'
        . '<th>Size</th><th>Modified</th><th>Name</th></tr>' . $rows . '</table><pre class="out">';
}

/**
 * Accept an upload, hash it for evidence, then discard it immediately.
 * Nothing attacker-supplied is ever written to disk.
 */
function simulate_upload(string $ip, array $identity): string
{
    if (empty($_FILES['file']) || !is_array($_FILES['file'])) {
        return '';
    }
    $file = $_FILES['file'];
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        return 'Upload failed.';
    }

    $tmp = (string)($file['tmp_name'] ?? '');
    $name = basename((string)($file['name'] ?? 'upload.bin'));
    $name = preg_replace('/[^A-Za-z0-9._-]/', '_', $name) ?: 'upload.bin';
    $size = (int)($file['size'] ?? 0);

    $sha256 = '';
    $mime = 'application/octet-stream';
    if ($tmp !== '' && is_uploaded_file($tmp)) {
        $sha256 = (string)@hash_file('sha256', $tmp);
        if (function_exists('finfo_open')) {
            $finfo = @finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo !== false) {
                $mime = (string)@finfo_file($finfo, $tmp) ?: $mime;
                @finfo_close($finfo);
            }
        }
        @unlink($tmp);   // discarded immediately -- content is never retained
    }

    score_event($ip, 'FILE_UPLOAD', "{$name} ({$size} bytes) sha256={$sha256}");
    activate_tarpit($ip, 'File upload via webshell');

    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => 'UPLOAD_DISCARDED',
        'filename' => $name,
        'size' => $size,
        'sha256' => $sha256,
        'mime' => $mime,
        'headers' => sb_request_headers(),
    ]);

    $target = '/var/www/html/uploads/' . $name;
    fs_add_file($ip, $target, $size);

    $message = "Upload successful. File saved to {$target} (Size: {$size} bytes).\n"
        . 'MD5: ' . md5($name . $size . $sha256) . "\n"
        . "SHA256: {$sha256}";

    if (preg_match('/\.(php|phtml|phar|php5|php7)$/i', $name)) {
        $wan = $identity['fake_wan_ip'] ?? '0.0.0.0';
        $message .= "\n\nWebshell accessible at: http://{$wan}/uploads/{$name}";
    }
    return $message;
}

// ------------------------------------------------------------------ info tabs

function network_overview(array $identity): string
{
    return sb_html(
        fake_ifconfig($identity) . "\n\n"
        . "--- Listening ports ---\n" . fake_netstat($identity) . "\n\n"
        . "--- ARP table ---\n"
        . "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
        . "10.0.1.1                 ether   00:1b:21:3c:4d:5e   C                     eth0\n"
        . str_pad(FAKE_LAST_LOGIN_FROM, 25) . "ether   00:50:56:9a:11:c2   C                     eth0\n"
        . "10.0.1.23                ether   00:50:56:9a:44:71   C                     eth0"
    );
}

/**
 * Scan the scanner: whatever they aimed at, the report comes back on them.
 *
 * Nothing is actually scanned. This container has no egress by design, and
 * scanning back would be a real port scan launched at a third party -- often a
 * victim's compromised box rather than the attacker's own -- as well as an
 * instant tell, since the packets would come from this host. So the port list
 * is fabricated deterministically from their address, like every other answer
 * in this shell.
 *
 * The observed block is not fabricated: it is what the honeypot has actually
 * recorded about them. Matches shared/fakeshell.py so both shells agree.
 */
function fake_scanback(string $ip, array $identity): string
{
    if (getenv('HONEYPOT_SCANBACK') === '0') {
        return "Starting Nmap 7.80 ( https://nmap.org ) at " . gmdate('Y-m-d H:i') . " UTC\n"
            . "WARNING: No targets were specified, so 0 hosts scanned.\n"
            . "Nmap done: 0 IP addresses (0 hosts up) scanned in 0.29 seconds";
    }

    $catalogue = [
        [21, 'ftp'], [22, 'ssh'], [23, 'telnet'], [25, 'smtp'], [53, 'domain'],
        [80, 'http'], [110, 'pop3'], [143, 'imap'], [443, 'https'],
        [445, 'microsoft-ds'], [993, 'imaps'], [995, 'pop3s'], [1723, 'pptp'],
        [3306, 'mysql'], [3389, 'ms-wbt-server'], [5900, 'vnc'],
        [8080, 'http-proxy'], [8443, 'https-alt'],
    ];

    // Seeded from their address so a rescan returns the same host, the way a
    // real one would.
    mt_srand(crc32($ip));
    $count = 2 + mt_rand(0, 2);
    $keys = array_rand($catalogue, $count);
    $keys = is_array($keys) ? $keys : [$keys];
    sort($keys);

    $rows = '';
    foreach ($keys as $key) {
        [$port, $name] = $catalogue[$key];
        $rows .= str_pad($port . '/tcp', 10) . 'open  ' . $name . "\n";
    }

    $touched = $identity['services_touched'] ?? [];
    $creds = count($identity['credentials'] ?? []);
    $events = count($identity['session_history'] ?? []);
    $firstSeen = substr((string)($identity['first_seen'] ?? ''), 0, 19);

    return "Starting Nmap 7.80 ( https://nmap.org ) at " . gmdate('Y-m-d H:i') . " UTC\n"
        . "Nmap scan report for {$ip}\n"
        . "Host is up (0.00" . mt_rand(11, 89) . "s latency).\n"
        . "Not shown: " . (1000 - $count) . " filtered ports\n"
        . "PORT      STATE SERVICE\n"
        . $rows . "\n"
        . "Host script results:\n"
        . "| clients-observed:\n"
        . "|   address: {$ip}\n"
        . "|   first seen: {$firstSeen}\n"
        . "|   sessions logged: {$events}\n"
        . "|   services probed: " . ($touched ? implode(', ', $touched) : 'http') . "\n"
        . "|   credentials offered: {$creds}\n"
        . "|_  threat score: " . number_format((float)($identity['score'] ?? 0), 0) . "\n\n"
        . "Nmap done: 1 IP address (1 host up) scanned in "
        . mt_rand(9, 26) . "." . mt_rand(10, 99) . " seconds";
}

function fake_nmap_scan(array $identity): string
{
    $lan = $identity['fake_lan_ip'] ?? '10.0.1.50';
    return "Starting Nmap 7.80 ( https://nmap.org ) at " . gmdate('Y-m-d H:i') . " UTC\n"
        . "Nmap scan report for 10.0.1.1\nHost is up (0.00042s latency).\n"
        . "PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\n\n"
        . "Nmap scan report for " . FAKE_LAST_LOGIN_FROM . "\nHost is up (0.00071s latency).\n"
        . "PORT     STATE SERVICE\n22/tcp   open  ssh\n445/tcp  open  microsoft-ds\n"
        . "3389/tcp open  ms-wbt-server\n\n"
        . "Nmap scan report for 10.0.1.23\nHost is up (0.00088s latency).\n"
        . "PORT     STATE SERVICE\n3306/tcp open  mysql\n6379/tcp open  redis\n\n"
        . "Nmap scan report for {$lan}\nHost is up (0.000090s latency).\n"
        . "PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n\n"
        . "Nmap done: 256 IP addresses (4 hosts up) scanned in 14.22 seconds";
}

function fake_phpinfo(array $identity): string
{
    $hostname = $identity['fake_hostname'] ?? 'prod-web-01';
    $kernel = $identity['fake_kernel'] ?? '5.15.0-86-generic';

    $extensions = ['Core', 'bcmath', 'calendar', 'ctype', 'curl', 'date', 'dom', 'exif',
        'fileinfo', 'filter', 'gd', 'gettext', 'hash', 'iconv', 'json', 'libxml',
        'mbstring', 'mysqli', 'mysqlnd', 'opcache', 'openssl', 'pcre', 'PDO',
        'pdo_mysql', 'Phar', 'posix', 'readline', 'Reflection', 'session',
        'SimpleXML', 'soap', 'sockets', 'SPL', 'standard', 'tokenizer', 'xml',
        'xmlreader', 'xmlwriter', 'xsl', 'zlib'];

    $out = "phpinfo()\n"
        . "PHP Version => " . FAKE_PHP_VERSION . "\n\n"
        . "System => Linux {$hostname} {$kernel} #1 SMP Debian x86_64\n"
        . "Build Date => Nov  2 2023 12:41:22\n"
        . "Server API => FPM/FastCGI\n"
        . "Virtual Directory Support => disabled\n"
        . "Configuration File (php.ini) Path => /etc/php/" . FAKE_PHP_SERIES . "/fpm\n"
        . "Loaded Configuration File => /etc/php/" . FAKE_PHP_SERIES . "/fpm/php.ini\n"
        . "Scan this dir for additional .ini files => /etc/php/" . FAKE_PHP_SERIES . "/fpm/conf.d\n"
        . "PHP API => 20190902\nPHP Extension => 20190902\nZend Extension => 320190902\n"
        . "Debug Build => no\nThread Safety => disabled\nZend Signal Handling => enabled\n"
        . "IPv6 Support => enabled\nRegistered PHP Streams => https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar\n\n"
        . "--- Configuration ---\n"
        . "allow_url_fopen => On => On\nallow_url_include => Off => Off\n"
        . "disable_functions => no value => no value\n"
        . "display_errors => Off => Off\nexpose_php => On => On\n"
        . "file_uploads => On => On\nmax_execution_time => 30 => 30\n"
        . "memory_limit => 128M => 128M\nopen_basedir => no value => no value\n"
        . "post_max_size => 20M => 20M\nupload_max_filesize => 20M => 20M\n"
        . "safe_mode => Off => Off\n\n"
        . "--- Loaded Modules ---\n";

    foreach (array_chunk($extensions, 6) as $chunk) {
        $out .= implode('  ', array_map(static fn($e) => str_pad($e, 13), $chunk)) . "\n";
    }

    $out .= "\n--- mysqli ---\n"
        . "Client API library version => mysqlnd " . FAKE_PHP_VERSION . "\n"
        . "Active Persistent Links => 0\nActive Links => 0\n\n"
        . "--- \$_SERVER ---\n"
        . "SERVER_SOFTWARE => " . FAKE_SERVER_SOFTWARE . "\n"
        . "SERVER_NAME => {$hostname}\n"
        . "SERVER_ADDR => " . ($identity['fake_lan_ip'] ?? '10.0.1.50') . "\n"
        . "DOCUMENT_ROOT => /var/www/html\n"
        . "SCRIPT_FILENAME => /var/www/html/index.php\n"
        . "USER => www-data\n\n"
        . "--- \$_ENV ---\n"
        . "DB_HOST => 127.0.0.1\nDB_NAME => " . FAKE_DB_NAME
        . "\nDB_USER => " . FAKE_DB_USER . "\n"
        . "DB_PASSWORD => " . FAKE_DB_PASSWORD . "\n"
        . "APP_KEY => " . FAKE_HONEYTOKEN_KEY . "\n";

    return sb_html($out);
}
