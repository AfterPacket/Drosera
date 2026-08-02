<?php
declare(strict_types=1);

/*
 * Drosera shared runtime.
 *
 * ZERO-TRUST CONTRACT -- every file that includes this one inherits it:
 *   - No exec/system/shell_exec/passthru/proc_open/popen, ever, on anything.
 *   - No eval() of attacker input, ever.
 *   - No include/require of an attacker-derived path.
 *   - Attacker-controlled strings never reach a real filesystem path.
 *   - All simulated state lives in Redis. The only writes to disk are appends to
 *     fixed paths under STORAGE_PATH, which nginx never serves.
 *
 * State is shared with the Python protocol honeypots: same Redis keys, same JSON
 * schema, so an attacker who hits the web shell and then SSH sees one machine.
 */

// --------------------------------------------------------------- configuration

define('STORAGE_PATH', getenv('STORAGE_PATH') ?: '/var/honeypot/storage');
define('REDIS_HOST', getenv('REDIS_HOST') ?: '127.0.0.1');
define('REDIS_PORT', (int)(getenv('REDIS_PORT') ?: 6379));
define('CF_IP_HEADER', 'HTTP_CF_CONNECTING_IP');
define('RATE_LIMIT_RPM', (int)(getenv('RATE_LIMIT_RPM') ?: 60));
define('BAN_THRESHOLD', (int)(getenv('HONEYPOT_BAN_THRESHOLD') ?: 35));
define('TARPIT_THRESHOLD', (int)(getenv('HONEYPOT_TARPIT_THRESHOLD') ?: 5));
define('CRASH_THRESHOLD', (int)(getenv('HONEYPOT_CRASH_THRESHOLD') ?: 15));
// Off switch for crash mode, matching shared/crash.py. Compared explicitly for
// the same reason HONEYPOT_RICKROLL is below: `?:` reads '0' as falsy and would
// silently re-enable the thing the operator just turned off.
define('CRASH_ENABLED', !in_array(
    strtolower(trim((string)getenv('HONEYPOT_CRASH'))),
    ['0', 'false', 'no', 'off'], true));
// How long an operator release holds. Shared with the tarpit release so a single
// dashboard action does not leave the two tiers on different deadlines.
define('TARPIT_RELEASE_SECONDS',
    (float)(getenv('HONEYPOT_TARPIT_RELEASE_SECONDS') ?: 3600));
define('RICKROLL_URL', getenv('RICKROLL_URL') ?: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');
// Compared explicitly rather than with ?:, which would read '0' as falsy and
// silently re-enable the thing the operator just turned off.
define('RICKROLL_ENABLED', !in_array(
    strtolower(trim((string)getenv('HONEYPOT_RICKROLL'))),
    ['0', 'false', 'no', 'off'], true));
define('RICKROLL_DRIP_SECONDS', (float)(getenv('HONEYPOT_RICKROLL_DRIP_SECONDS') ?: 120));
// shared/rickroll.txt, bind-mounted into this container. It cannot live beside
// this file: /var/www/html is a read-only bind mount and Docker cannot create a
// mountpoint inside one, so the container would refuse to start. It is mounted
// at the root instead -- see the `web` service in docker-compose.yml.
//
// The __DIR__ fallback is for running the site outside compose. Absent the file
// entirely the redirect still happens, which is why its absence is a preflight
// check rather than something you would notice in the logs.
define('RICKROLL_FILE', getenv('RICKROLL_FILE') ?: __DIR__ . '/rickroll.txt');

// The machine this deployment pretends to be. Not hardcoded: these strings are
// the most-observed thing the honeypot emits, and a value published in this
// repository identifies any host still using it. See web/lib/persona.php.
require_once __DIR__ . '/persona.php';

define('FAKE_PHP_VERSION', (string)sb_persona('php_version'));
define('FAKE_MYSQL_VERSION', (string)sb_persona('mysql_version'));
define('FAKE_SERVER_SOFTWARE', (string)sb_persona('http_server'));
define('COMPANY_NAME', (string)sb_persona('company_name'));
define('COMPANY_SHORT', (string)sb_persona('company_short'));
define('COMPANY_ADDRESS', (string)sb_persona('company_address'));
define('COMPANY_FOUNDED', (int)sb_persona('company_founded'));
define('COMPANY_PHONE', (string)sb_persona('company_phone'));
define('COMPANY_ENTITY', (string)sb_persona('company_entity'));
define('COMPANY_TAGLINE', (string)sb_persona('company_tagline'));
define('COMPANY_KEYWORDS', (string)sb_persona('company_keywords'));
define('FAKE_DB_NAME', (string)sb_persona('db_name'));
define('FAKE_DB_USER', (string)sb_persona('db_user'));
define('FAKE_DB_PASSWORD', (string)sb_persona('db_password'));
define('FAKE_HONEYTOKEN_KEY', (string)sb_persona('honeytoken_key'));
define('COMPANY_DOMAIN', (string)sb_persona('company_domain'));
define('COMPANY_SLUG', (string)sb_persona('company_slug'));
define('FAKE_AWS_KEY_ID', (string)sb_persona('aws_access_key_id'));
define('FAKE_AWS_KEY_ID_STAGING', (string)sb_persona('aws_access_key_id_staging'));
define('FAKE_MAIL_PASSWORD', (string)sb_persona('mail_password'));
define('FAKE_STAGING_IP', (string)sb_persona('staging_ip'));
define('FAKE_LAST_LOGIN_FROM', (string)sb_persona('last_login_from'));
// Series only: /etc/php/8.2/fpm/php.ini, never /etc/php/8.2.7/fpm/php.ini.
define('FAKE_PHP_SERIES', implode('.', array_slice(explode('.', FAKE_PHP_VERSION), 0, 2)));
define('WEBSHELL_PATH', '/wp-admin/admin-ajax.php');
// Magic ?action= value that unlocks the shell UI. Looks like an ordinary
// WordPress AJAX hook so it does not stand out in a log or a wordlist.
define('WEBSHELL_ACTION', getenv('WEBSHELL_ACTION') ?: 'wp_ajax_nopriv_media_upload');

define('TARPIT_RATE_BYTES_PER_CHUNK', 150);
define('TARPIT_CHUNK_DELAY_US', 50000);          // ~3 KB/s
// Fail-safe: a tarpit pins one PHP-FPM worker. Cap total concurrent tarpits and
// per-request duration so a flood can never starve the pool and take the site down.
define('TARPIT_MAX_CONCURRENT', (int)(getenv('TARPIT_MAX_CONCURRENT') ?: 24));
define('TARPIT_MAX_SECONDS', (int)(getenv('TARPIT_MAX_SECONDS') ?: 900));

define('IDENTITY_TTL', 7 * 24 * 3600);
define('BAN_TTL', (int)(getenv('HONEYPOT_BAN_TTL') ?: 7 * 24 * 3600));
define('MAX_HISTORY', 200);
define('MAX_LOG_VALUE', 1000);
define('MAX_STORAGE_MB', (int)(getenv('HONEYPOT_MAX_STORAGE_MB') ?: 4096));

// Webshell commands from one IP group into a single recording until this many
// seconds pass with no new command.
define('CAM_WEB_IDLE_SECONDS', (int)(getenv('CAM_WEB_IDLE_SECONDS') ?: 900));
define('CAM_MAX_SESSION_BYTES', (int)(getenv('HONEYPOT_MAX_SESSION_BYTES') ?: 2097152));
// Whether scanner probes and tarpit drips are recorded alongside webshell
// commands. On by default: they are most of what arrives, and a live feed that
// only ever shows the rare webshell session under-reports the appliance badly.
// Set false on a deployment where the extra file churn per probe is unwelcome.
define('CAM_RECORD_WEB_PROBES',
    strtolower((string)(getenv('CAM_RECORD_WEB_PROBES') ?: 'true')) !== 'false');

const SCORES = [
    'CONNECTION_ANY'      => [1,  'Initial contact'],
    'RECON_LS'            => [1,  'Directory enumeration'],
    'READ_PASSWD'         => [3,  'Read /etc/passwd'],
    'READ_SHADOW'         => [5,  'Read /etc/shadow'],
    'PROCESS_ENUM'        => [2,  'Process enumeration'],
    'NETWORK_ENUM'        => [3,  'Network enumeration'],
    'DOCKER_K8S_ENUM'     => [4,  'Container/orchestrator enumeration'],
    'SQLI_BASIC'          => [8,  'SQL injection pattern'],
    'SQLI_UNION_BLIND'    => [10, 'UNION/blind SQL injection'],
    'SQLI_OOB'            => [12, 'Out-of-band SQL injection attempt'],
    'PHP_EVAL_ATTEMPT'    => [7,  'PHP code execution attempt'],
    'FILE_UPLOAD'         => [8,  'Malicious file upload'],
    'WEBSHELL_CMD'        => [2,  'Webshell command issued'],
    'REVERSE_SHELL'       => [12, 'Reverse shell payload'],
    'CREDENTIAL_ATTEMPT'  => [2,  'Login credential attempt'],
    'CREDENTIAL_SPRAY'    => [6,  'Credential spraying'],
    'RATE_LIMIT_ABUSE'    => [4,  'Rate limit exceeded'],
    'SMB_ENUM'            => [5,  'SMB share enumeration'],
    'RDP_CONNECT'         => [3,  'RDP connection attempt'],
    'FTP_ANON'            => [2,  'Anonymous FTP attempt'],
    'SMTP_RELAY'          => [6,  'Open relay attempt'],
    'SCANNER_PATH_HIT'    => [2,  'Known scanner path accessed'],
    'TARPIT_ENGAGED'      => [0,  'Tarpit activated for IP'],
    'TOOL_SQLMAP'         => [5,  'sqlmap detected'],
    'TOOL_METASPLOIT'     => [8,  'Metasploit detected'],
    'TOOL_NUCLEI'         => [3,  'Nuclei detected'],
    'TOOL_NIKTO'          => [3,  'Nikto detected'],
    'TOOL_HYDRA'          => [4,  'Hydra detected'],
    'TOOL_MASSCAN'        => [3,  'Masscan detected'],
    'TOOL_NMAP'           => [5,  'Nmap detected'],
    'TOOL_OTHER'          => [2,  'Automated scanner detected'],
    'CRASH_ENGAGED'       => [0,  'Crash mode activated for IP'],
    'CRASH_RELEASED'      => [0,  'Crash mode released for IP'],
];

/* Cloudflare edge ranges. CF-Connecting-IP is honoured only from these peers. */
const CLOUDFLARE_CIDRS = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

// ------------------------------------------------------------------ Redis client

/**
 * Minimal Redis client. Prefers the phpredis extension when present and falls
 * back to a raw RESP implementation over fsockopen so the honeypot has no hard
 * dependency on any extension.
 */
final class RedisClient
{
    private $socket = null;
    private $native = null;
    private bool $failed = false;

    public function __construct(string $host = REDIS_HOST, int $port = REDIS_PORT)
    {
        if (class_exists('Redis')) {
            try {
                $native = new Redis();
                if (@$native->connect($host, $port, 2.0)) {
                    $native->setOption(Redis::OPT_READ_TIMEOUT, 3.0);
                    $this->native = $native;
                    return;
                }
            } catch (Throwable $e) {
                $this->native = null;
            }
        }
        // Host and port come from the environment, never from a request.
        $socket = @fsockopen($host, $port, $errno, $errstr, 2.0);
        if ($socket === false) {
            error_log("drosera: redis connect failed: {$errstr}");
            $this->failed = true;
            return;
        }
        stream_set_timeout($socket, 3);
        $this->socket = $socket;
    }

    public function isReady(): bool
    {
        return !$this->failed && ($this->native !== null || $this->socket !== null);
    }

    /** Encode and send a command, then read one reply. */
    private function call(string $command, array $args = [])
    {
        if ($this->native !== null) {
            try {
                return $this->native->rawCommand($command, ...$args);
            } catch (Throwable $e) {
                return null;
            }
        }
        if ($this->socket === null) {
            return null;
        }

        $parts = array_merge([$command], array_map('strval', $args));
        $payload = '*' . count($parts) . "\r\n";
        foreach ($parts as $part) {
            $payload .= '$' . strlen($part) . "\r\n" . $part . "\r\n";
        }

        if (@fwrite($this->socket, $payload) === false) {
            $this->failed = true;
            return null;
        }
        return $this->readReply();
    }

    private function readReply()
    {
        $line = @fgets($this->socket);
        if ($line === false || $line === '') {
            $this->failed = true;
            return null;
        }
        $type = $line[0];
        $body = substr($line, 1, -2);

        switch ($type) {
            case '+':
                return $body;
            case '-':
                error_log('drosera: redis error: ' . $body);
                return false;
            case ':':
                return (int)$body;
            case '$':
                $length = (int)$body;
                if ($length === -1) {
                    return null;
                }
                $data = '';
                while (strlen($data) < $length) {
                    $chunk = @fread($this->socket, $length - strlen($data));
                    if ($chunk === false || $chunk === '') {
                        $this->failed = true;
                        return null;
                    }
                    $data .= $chunk;
                }
                @fread($this->socket, 2);
                return $data;
            case '*':
                $count = (int)$body;
                if ($count === -1) {
                    return null;
                }
                $items = [];
                for ($i = 0; $i < $count; $i++) {
                    $items[] = $this->readReply();
                }
                return $items;
            default:
                return null;
        }
    }

    public function ping() { return $this->call('PING'); }
    public function get(string $k) { return $this->call('GET', [$k]); }
    public function set(string $k, string $v) { return $this->call('SET', [$k, $v]); }
    public function setex(string $k, int $ttl, string $v) { return $this->call('SETEX', [$k, $ttl, $v]); }
    public function del(string $k) { return $this->call('DEL', [$k]); }
    public function exists(string $k) { return (int)$this->call('EXISTS', [$k]); }
    public function expire(string $k, int $ttl) { return $this->call('EXPIRE', [$k, $ttl]); }
    public function incr(string $k) { return $this->call('INCR', [$k]); }
    public function decr(string $k) { return $this->call('DECR', [$k]); }
    public function zadd(string $k, float $score, string $m) { return $this->call('ZADD', [$k, $score, $m]); }
    public function zremrangebyscore(string $k, string $min, string $max) { return $this->call('ZREMRANGEBYSCORE', [$k, $min, $max]); }
    public function zcard(string $k) { return (int)$this->call('ZCARD', [$k]); }
    public function hget(string $k, string $f) { return $this->call('HGET', [$k, $f]); }
    public function hset(string $k, string $f, string $v) { return $this->call('HSET', [$k, $f, $v]); }
    public function hgetall(string $k) { return $this->call('HGETALL', [$k]); }
    public function hincrby(string $k, string $f, int $n) { return $this->call('HINCRBY', [$k, $f, $n]); }
    public function hincrbyfloat(string $k, string $f, float $n) { return $this->call('HINCRBYFLOAT', [$k, $f, $n]); }
    public function lpush(string $k, string $v) { return $this->call('LPUSH', [$k, $v]); }
    public function ltrim(string $k, int $s, int $e) { return $this->call('LTRIM', [$k, $s, $e]); }
    public function lrange(string $k, int $s, int $e) { return $this->call('LRANGE', [$k, $s, $e]); }
    public function keys(string $pattern) { return $this->call('KEYS', [$pattern]); }

    public function close(): void
    {
        if ($this->native !== null) {
            try { $this->native->close(); } catch (Throwable $e) {}
            $this->native = null;
        }
        if ($this->socket !== null) {
            @fclose($this->socket);
            $this->socket = null;
        }
    }
}

function sb_redis(): RedisClient
{
    static $client = null;
    if ($client === null) {
        $client = new RedisClient();
    }
    return $client;
}

// ------------------------------------------------------------------ IP handling

function sb_ip_in_cidr(string $ip, string $cidr): bool
{
    [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
    if ($bits === null) {
        return $ip === $subnet;
    }
    $bits = (int)$bits;
    $ipBin = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
        return false;
    }
    $bytes = intdiv($bits, 8);
    $remainder = $bits % 8;
    if ($bytes > 0 && strncmp($ipBin, $subnetBin, $bytes) !== 0) {
        return false;
    }
    if ($remainder === 0) {
        return true;
    }
    $mask = chr(0xFF << (8 - $remainder) & 0xFF);
    return (($ipBin[$bytes] & $mask) === ($subnetBin[$bytes] & $mask));
}

function sb_peer_is_cloudflare(string $ip): bool
{
    foreach (CLOUDFLARE_CIDRS as $cidr) {
        if (sb_ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * Resolve the attacker's real address.
 *
 * CF-Connecting-IP is trusted only when the TCP peer is genuinely a Cloudflare
 * edge node; otherwise anyone could forge their source address and poison the
 * scoring of an unrelated IP. X-Forwarded-For is never trusted.
 */
function get_real_ip(): string
{
    $peer = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && sb_peer_is_cloudflare($peer)) {
        $candidate = filter_var(trim($_SERVER['HTTP_CF_CONNECTING_IP']), FILTER_VALIDATE_IP);
        if ($candidate !== false) {
            return $candidate;
        }
    }
    // X-Real-IP is set by our own nginx from the TCP peer, so it is safe.
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $candidate = filter_var(trim($_SERVER['HTTP_X_REAL_IP']), FILTER_VALIDATE_IP);
        if ($candidate !== false) {
            return $candidate;
        }
    }
    return filter_var($peer, FILTER_VALIDATE_IP) ?: '0.0.0.0';
}

function sb_ip_hash(string $ip): string
{
    return md5($ip);
}

// ----------------------------------------------------------------- fake identity

function sb_seeded_pick(array $pool, int &$seed)
{
    // Deterministic LCG so identity generation never touches global rand state.
    $seed = ($seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return $pool[$seed % count($pool)];
}

function sb_seeded_int(int $min, int $max, int &$seed): int
{
    $seed = ($seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return $min + ($seed % max(1, ($max - $min + 1)));
}

function sb_generate_identity(string $ip): array
{
    $seed = crc32($ip) & 0x7FFFFFFF;

    $hostnames = ['prod-web-01', 'prod-web-02', 'prod-db-01', 'prod-cache-01',
                  'mail-srv-01', 'api-gateway-01', 'proxy-01', 'app-node-03',
                  'backup-srv', 'monitoring-01', 'vpn-gateway', 'srv-colo-04'];
    $kernels = ['5.15.0-86-generic', '5.15.0-91-generic', '5.10.0-21-amd64',
                '5.4.0-150-generic', '4.19.0-23-amd64', '6.1.0-13-amd64'];
    $oses = ['Ubuntu 22.04.3 LTS', 'Ubuntu 20.04.6 LTS',
             'Debian GNU/Linux 11 (bullseye)', 'Debian GNU/Linux 12 (bookworm)',
             'CentOS Linux 7 (Core)', 'AlmaLinux 8.9'];
    $humans = [['jmarsh', '/home/jmarsh'], ['dkowalski', '/home/dkowalski'],
               ['rchen', '/home/rchen'], ['aokafor', '/home/aokafor'],
               ['tbergman', '/home/tbergman'], ['lnguyen', '/home/lnguyen']];

    $hostname = sb_seeded_pick($hostnames, $seed);
    $kernel = sb_seeded_pick($kernels, $seed);
    $os = sb_seeded_pick($oses, $seed);
    $lan = '10.0.1.' . sb_seeded_int(20, 240, $seed);
    $wan = sb_seeded_pick([45, 51, 68, 104, 138, 159, 167, 178], $seed)
        . '.' . sb_seeded_int(1, 254, $seed)
        . '.' . sb_seeded_int(1, 254, $seed)
        . '.' . sb_seeded_int(2, 253, $seed);

    $mac = '02';
    for ($i = 0; $i < 5; $i++) {
        $mac .= ':' . sprintf('%02x', sb_seeded_int(0, 255, $seed));
    }

    $users = [
        ['username' => 'root', 'uid' => 0, 'gid' => 0, 'home' => '/root',
         'shell' => '/bin/bash', 'groups' => ['root']],
        ['username' => 'www-data', 'uid' => 33, 'gid' => 33, 'home' => '/var/www',
         'shell' => '/usr/sbin/nologin', 'groups' => ['www-data']],
    ];
    // Bounded: the LCG advances every call, but never let a pathological seed
    // spin here. Falling through with fewer than 3 users is harmless.
    $picked = [];
    for ($attempt = 0; $attempt < 40 && count($picked) < 3; $attempt++) {
        $candidate = sb_seeded_pick($humans, $seed);
        if (!in_array($candidate[0], array_column($picked, 0), true)) {
            $picked[] = $candidate;
        }
    }
    foreach ($picked as $i => [$name, $home]) {
        $users[] = [
            'username' => $name, 'uid' => 1000 + $i, 'gid' => 1000 + $i,
            'home' => $home, 'shell' => '/bin/bash',
            'groups' => ['sudo', 'www-data'],
        ];
    }

    return [
        // Stored plainly: the Redis key is md5(ip), which is one-way, and the
        // dashboard needs the real address to render and to action bans.
        'ip' => $ip,
        'fake_hostname' => $hostname,
        'fake_kernel' => $kernel,
        'fake_os' => $os,
        'fake_lan_ip' => $lan,
        'fake_wan_ip' => $wan,
        'fake_mac' => $mac,
        'fake_webroot' => '/var/www/html',
        'fake_users' => $users,
        'fake_cwd' => '/var/www/html',
        'fake_filesystem' => sb_initial_filesystem(),
        'score' => 0,
        'tool_detected' => null,
        'tarpit_active' => false,
        'tarpit_exempt_until' => 0,
        'crash_active' => false,
        'crash_exempt_until' => 0,
        'services_touched' => [],
        'session_history' => [],
        'credentials' => [],
        'banned' => false,
        'rickroll' => false,
        'first_seen' => gmdate('c'),
        'last_seen' => gmdate('c'),
    ];
}

function sb_dir(array $children = []): array
{
    return ['type' => 'dir', 'mode' => 'drwxr-xr-x', 'children' => $children];
}

function sb_file(int $size, string $mode = '-rw-r--r--'): array
{
    return ['type' => 'file', 'mode' => $mode, 'size' => $size];
}

function sb_initial_filesystem(): array
{
    return sb_dir([
        'etc' => sb_dir([
            'passwd' => sb_file(2114),
            'shadow' => sb_file(1387, '-rw-r-----'),
            'hostname' => sb_file(14),
            'hosts' => sb_file(221),
            'resolv.conf' => sb_file(78),
            'crontab' => sb_file(1042),
            'os-release' => sb_file(386),
            'nginx' => sb_dir(['nginx.conf' => sb_file(1482)]),
            'mysql' => sb_dir(['my.cnf' => sb_file(682)]),
        ]),
        'var' => sb_dir([
            'www' => sb_dir([
                'html' => sb_dir([
                    'index.php' => sb_file(418),
                    'wp-config.php' => sb_file(3214),
                    'wp-load.php' => sb_file(3843),
                    'xmlrpc.php' => sb_file(3236),
                    '.htaccess' => sb_file(235),
                    'wp-content' => sb_dir([
                        'uploads' => sb_dir([
                            '2024' => sb_dir([
                                '01' => sb_dir([
                                    'strategic-plan-2024.pdf' => sb_file(284918),
                                ]),
                            ]),
                        ]),
                        'plugins' => sb_dir(),
                        'themes' => sb_dir(),
                    ]),
                    'uploads' => sb_dir(),
                ]),
            ]),
            'log' => sb_dir(['syslog' => sb_file(1048576), 'auth.log' => sb_file(204800)]),
            'backups' => sb_dir(['db-backup-2024-01-14.sql.gz' => sb_file(48211904)]),
        ]),
        'home' => sb_dir(),
        'root' => sb_dir([
            '.bash_history' => sb_file(1841),
            '.ssh' => sb_dir(['id_rsa' => sb_file(1679, '-rw-------')]),
        ]),
        'opt' => sb_dir(['monitoring' => sb_dir(['check.php' => sb_file(2140)])]),
        'tmp' => sb_dir(),
    ]);
}

function sb_identity_key(string $ip): string
{
    return 'hp:identity:' . sb_ip_hash($ip);
}

/**
 * Addresses that are never scored, tarpitted, banned or stored.
 *
 * The web tier keeps its own identity store in PHP, so it needs its own copy of
 * this check -- HONEYPOT_IGNORE_IPS was read only by shared/identity.py, which
 * meant an operator who added their own address still got scored and eventually
 * banned by browsing their own site. That is the precise scenario the setting
 * exists to prevent, and on the web tier it never worked.
 *
 * The bridge gateway is included automatically. It is the host reaching in --
 * health checks and anything curled from the box -- and it climbed to 27 of the
 * 35-point ban threshold before anyone noticed. A ban there would have had
 * fail2ban run `ufw insert 1 deny from <gateway>`, cutting the host off from
 * every container it runs.
 *
 * Accepts single addresses and CIDR ranges, matching the Python side.
 */
function sb_ignored_networks(): array
{
    static $networks = null;
    if ($networks !== null) {
        return $networks;
    }

    $networks = [];
    foreach (explode(',', (string)getenv('HONEYPOT_IGNORE_IPS')) as $item) {
        $item = trim($item);
        if ($item !== '') {
            $networks[] = $item;
        }
    }

    $gatewayOff = in_array(
        strtolower(trim((string)(getenv('HONEYPOT_IGNORE_GATEWAY') ?: '1'))),
        ['0', 'false', 'no', 'off'], true);
    if (!$gatewayOff) {
        // Same source as the Python side: the container's default route.
        $route = @file('/proc/net/route', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach (($route ?: []) as $index => $line) {
            if ($index === 0) {
                continue;                                   // header
            }
            $fields = preg_split('/\s+/', $line);
            if (count($fields) > 2 && $fields[1] === '00000000'
                && $fields[2] !== '00000000') {
                $packed = str_pad(strrev(hex2bin(str_pad($fields[2], 8, '0', STR_PAD_LEFT))), 4, "\0");
                $networks[] = inet_ntop($packed);
                break;
            }
        }
    }
    return $networks;
}

function sb_is_ignored(string $ip): bool
{
    $address = @inet_pton($ip);
    if ($address === false) {
        return false;
    }
    foreach (sb_ignored_networks() as $entry) {
        if (strpos($entry, '/') === false) {
            if ($entry === $ip) {
                return true;
            }
            continue;
        }
        [$subnet, $bits] = explode('/', $entry, 2);
        $subnetPacked = @inet_pton($subnet);
        $bits = (int)$bits;
        if ($subnetPacked === false || strlen($subnetPacked) !== strlen($address)) {
            continue;
        }
        $whole = intdiv($bits, 8);
        $remainder = $bits % 8;
        if (strncmp($address, $subnetPacked, $whole) !== 0) {
            continue;
        }
        if ($remainder === 0) {
            return true;
        }
        $mask = chr((0xFF << (8 - $remainder)) & 0xFF);
        if ((substr($address, $whole, 1) & $mask)
            === (substr($subnetPacked, $whole, 1) & $mask)) {
            return true;
        }
    }
    return false;
}

function get_or_create_identity(string $ip): array
{
    // Generated but never stored, so an ignored address leaves no profile to
    // appear on the dashboard and nothing for the statistics to count.
    if (sb_is_ignored($ip)) {
        return sb_generate_identity($ip);
    }

    $redis = sb_redis();
    $key = sb_identity_key($ip);

    if ($redis->isReady()) {
        $cached = $redis->get($key);
        if (is_string($cached) && $cached !== '') {
            $decoded = json_decode($cached, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }
    }

    $identity = sb_generate_identity($ip);
    if ($redis->isReady()) {
        $redis->setex($key, IDENTITY_TTL, json_encode($identity));
    }
    return $identity;
}

function update_identity(string $ip, array $fields): array
{
    $identity = get_or_create_identity($ip);
    foreach ($fields as $name => $value) {
        $identity[$name] = $value;
    }
    $identity['last_seen'] = gmdate('c');

    // Merged for the caller, never written back. This is what kept refreshing
    // last_seen on the gateway's profile after scoring had already stopped
    // ignoring it -- the row stayed alive on the dashboard, ticking, with no
    // events behind it.
    if (sb_is_ignored($ip)) {
        return $identity;
    }

    $redis = sb_redis();
    if ($redis->isReady()) {
        $redis->setex(sb_identity_key($ip), IDENTITY_TTL, json_encode($identity));
    }
    return $identity;
}

/**
 * Whether an operator has released this address from the tarpit.
 *
 * Clearing `tarpit_active` alone lasts one request: the score is unchanged, so
 * the next scored event puts it straight back. The web tier has to honour the
 * same exemption as the Python services or a release from the dashboard would
 * survive on SSH and be undone by the first HTTP request.
 */
function sb_tarpit_exempt(array $identity): bool
{
    return (float)($identity['tarpit_exempt_until'] ?? 0) > microtime(true);
}

/** The same, for an operator unban. See identity.is_ban_exempt. */
function sb_ban_exempt(array $identity): bool
{
    return (float)($identity['ban_exempt_until'] ?? 0) > microtime(true);
}

function is_tarpitted(string $ip): bool
{
    if (sb_is_ignored($ip)) {
        return false;
    }
    $identity = get_or_create_identity($ip);
    if (sb_tarpit_exempt($identity)) {
        return false;
    }
    return !empty($identity['tarpit_active']);
}

function is_banned(string $ip): bool
{
    if (sb_is_ignored($ip)) {
        return false;
    }
    $redis = sb_redis();
    return $redis->isReady() && $redis->exists('hp:banned:' . sb_ip_hash($ip)) > 0;
}

function activate_tarpit(string $ip, string $reason = 'Threshold reached'): void
{
    if (sb_is_ignored($ip)) {
        return;
    }
    $identity = get_or_create_identity($ip);
    if (sb_tarpit_exempt($identity)) {
        return;
    }
    if (!empty($identity['tarpit_active'])) {
        return;
    }
    update_identity($ip, ['tarpit_active' => true]);
    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => 'TARPIT_ENGAGED',
        'reason' => $reason,
        'cumulative_score' => (float)($identity['score'] ?? 0),
        'tarpit_active' => true,
        'fake_hostname' => $identity['fake_hostname'] ?? '',
    ]);
}

function ban_ip(string $ip, float $score, string $reason, string $tool = '', string $services = ''): void
{
    $redis = sb_redis();
    if ($redis->isReady()) {
        $redis->setex('hp:banned:' . sb_ip_hash($ip), BAN_TTL, '1');
    }
    update_identity($ip, ['banned' => true, 'rickroll' => true]);

    // This line is what fail2ban watches to drive the host firewall.
    sb_append_line(
        STORAGE_PATH . '/evidence/fail2ban.log',
        sprintf("[%s] HONEYPOT_BAN ip=%s score=%s reason=%s tool=%s services=%s\n",
            gmdate('Y-m-d H:i:s'), $ip, $score, $reason ?: 'THRESHOLD',
            $tool ?: 'none', $services ?: 'none')
    );
    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => 'BAN',
        'reason' => $reason,
        'cumulative_score' => $score,
        'tool_detected' => $tool,
        'banned' => true,
    ]);
}

/** The same again, for crash mode. See identity.is_crash_exempt. */
function sb_crash_exempt(array $identity): bool
{
    return (float)($identity['crash_exempt_until'] ?? 0) > microtime(true);
}

function sb_is_crashed(string $ip): bool
{
    if (sb_is_ignored($ip)) {
        return false;
    }
    // Turning the feature off releases every address already flagged, in the
    // stored record rather than only in what this returns -- see
    // identity.is_crashed(), which this must not drift from. The write happens
    // once per flagged address, because the release clears the flag.
    if (!CRASH_ENABLED) {
        $identity = get_or_create_identity($ip);
        if (!empty($identity['crash_active'])) {
            sb_release_crash($ip, 'Crash mode disabled (HONEYPOT_CRASH=0)');
        }
        return false;
    }
    $identity = get_or_create_identity($ip);
    if (sb_crash_exempt($identity)) {
        return false;
    }
    return !empty($identity['crash_active']);
}

function sb_activate_crash(string $ip, string $reason = 'Threshold reached'): void
{
    // Ignored addresses are not data points, and a released one is not put back
    // by the first request after the release -- the score is still over the
    // threshold, which is the whole reason the exemption carries a deadline.
    if (!CRASH_ENABLED || sb_is_ignored($ip)) {
        return;
    }
    $identity = get_or_create_identity($ip);
    if (!empty($identity['crash_active']) || sb_crash_exempt($identity)) {
        return;
    }
    $identity = update_identity($ip, ['crash_active' => true]);
    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => 'CRASH_ENGAGED',
        'reason' => $reason,
        'cumulative_score' => (float)($identity['score'] ?? 0),
        'crash_active' => true,
        'fake_hostname' => $identity['fake_hostname'] ?? '',
    ]);
}

/** Counterpart to sb_activate_crash. See identity.release_crash. */
function sb_release_crash(string $ip, string $reason = 'Operator release'): void
{
    $identity = update_identity($ip, [
        'crash_active' => false,
        'crash_exempt_until' => microtime(true) + TARPIT_RELEASE_SECONDS,
    ]);
    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => 'CRASH_RELEASED',
        'reason' => $reason,
        'cumulative_score' => (float)($identity['score'] ?? 0),
        'crash_active' => false,
    ]);
}

/**
 * Apply points to an IP, append to its history, and escalate to tarpit/ban.
 */
function score_event(string $ip, string $eventType, string $payload = '', string $tool = ''): array
{
    // No identity, no score, no log line. The operator is not a data point.
    if (sb_is_ignored($ip)) {
        return ['old_score' => 0.0, 'new_score' => 0.0, 'banned' => false,
                'tarpit_active' => false, 'newly_tarpitted' => false,
                'ignored' => true];
    }

    [$points, $reason] = SCORES[$eventType] ?? [0, 'Unknown event'];

    $identity = get_or_create_identity($ip);
    $old = (float)($identity['score'] ?? 0);
    $new = $old + $points;

    $history = is_array($identity['session_history'] ?? null) ? $identity['session_history'] : [];
    $history[] = [
        'timestamp' => gmdate('c'),
        'event_type' => $eventType,
        'points' => $points,
        'reason' => $reason,
        'tool' => $tool,
        'service' => 'web',
        'payload' => mb_substr($payload, 0, 500),
    ];
    if (count($history) > MAX_HISTORY) {
        $history = array_slice($history, -MAX_HISTORY);
    }

    $services = is_array($identity['services_touched'] ?? null) ? $identity['services_touched'] : [];
    if (!in_array('web', $services, true)) {
        $services[] = 'web';
    }

    $fields = [
        'score' => $new,
        'session_history' => $history,
        'services_touched' => $services,
    ];
    if ($tool !== '') {
        $fields['tool_detected'] = $tool;
    }
    $wasTarpitted = !empty($identity['tarpit_active']);
    // Not while released. The score stays over the threshold after a release,
    // so without this every scored request re-engages the tarpit immediately.
    if ($new >= TARPIT_THRESHOLD && !sb_tarpit_exempt($identity)) {
        $fields['tarpit_active'] = true;
    }
    $identity = update_identity($ip, $fields);

    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => $eventType,
        'reason' => $reason,
        'payload_excerpt' => mb_substr($payload, 0, 500),
        'score_delta' => $points,
        'cumulative_score' => $new,
        'tool_detected' => $tool ?: ($identity['tool_detected'] ?? null),
        'tarpit_active' => !empty($identity['tarpit_active']),
        'services_touched' => implode(',', $services),
        'fake_hostname' => $identity['fake_hostname'] ?? '',
        'banned' => !empty($identity['banned']),
        'headers' => sb_request_headers(),
    ]);

    // Not while unbanned. The score is unchanged by an unban, so without this
    // the next scored request re-bans -- and writes another fail2ban line, so
    // lifting a ban would add a firewall rule instead of removing one.
    if ($new >= BAN_THRESHOLD && empty($identity['banned'])
        && !sb_ban_exempt($identity)) {
        ban_ip($ip, $new, $eventType, $tool, implode(',', $services));
        $identity['banned'] = true;
    }

    return [
        'old_score' => $old,
        'new_score' => $new,
        'points' => $points,
        'reason' => $reason,
        'identity' => $identity,
        'newly_tarpitted' => !$wasTarpitted && !empty($identity['tarpit_active']),
    ];
}

// ---------------------------------------------------------------------- logging

function sb_storage_ok(): bool
{
    static $checked = null;
    if ($checked !== null) {
        return $checked;
    }
    // Fail-safe: stop appending once storage is oversized so a sustained attack
    // cannot fill the VPS disk and knock the box over.
    $free = @disk_free_space(STORAGE_PATH);
    $checked = ($free === false) || ($free > 512 * 1024 * 1024);
    return $checked;
}

function sb_append_line(string $path, string $line): void
{
    if (!sb_storage_ok()) {
        return;
    }
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }
    $handle = @fopen($path, 'a');
    if ($handle === false) {
        return;
    }
    @flock($handle, LOCK_EX);
    @fwrite($handle, $line);
    @flock($handle, LOCK_UN);
    @fclose($handle);
}

/**
 * MITRE ATT&CK technique per event type, as [id, name].
 *
 * Kept in step with shared/scoring.py by hand, because the two tiers do not
 * share code. Only the web tier's own event types are listed -- the Python
 * services write theirs through shared/alerting.py and never come through
 * here.
 */
const TECHNIQUES = [
    'CREDENTIAL_ATTEMPT'  => ['T1110', 'Brute Force'],
    'CREDENTIAL_SPRAY'    => ['T1110.003', 'Password Spraying'],
    'WEBSHELL_CMD'        => ['T1059', 'Command and Scripting Interpreter'],
    'PHP_EVAL_ATTEMPT'    => ['T1059.004', 'Unix Shell'],
    'REVERSE_SHELL'       => ['T1071', 'Application Layer Protocol'],
    'FILE_UPLOAD'         => ['T1105', 'Ingress Tool Transfer'],
    'SQLI_BASIC'          => ['T1190', 'Exploit Public-Facing Application'],
    'SQLI_UNION_BLIND'    => ['T1190', 'Exploit Public-Facing Application'],
    'SQLI_OOB'            => ['T1190', 'Exploit Public-Facing Application'],
    'SCANNER_PATH_HIT'    => ['T1595.003', 'Active Scanning: Wordlist Scanning'],
    'RECON_LS'            => ['T1083', 'File and Directory Discovery'],
    'READ_PASSWD'         => ['T1003.008', 'OS Credential Dumping: /etc/passwd'],
    'READ_SHADOW'         => ['T1003.008', 'OS Credential Dumping: /etc/shadow'],
    'PROCESS_ENUM'        => ['T1057', 'Process Discovery'],
    'NETWORK_ENUM'        => ['T1046', 'Network Service Discovery'],
    'DOCKER_K8S_ENUM'     => ['T1613', 'Container and Resource Discovery'],
    'RATE_LIMIT_ABUSE'    => ['T1499', 'Endpoint Denial of Service'],
    'PERSISTENCE_ATTEMPT' => ['T1098.004', 'SSH Authorized Keys'],
    'TOOL_SQLMAP'         => ['T1595.002', 'Vulnerability Scanning'],
    'TOOL_NUCLEI'         => ['T1595.002', 'Vulnerability Scanning'],
    'TOOL_NIKTO'          => ['T1595.002', 'Vulnerability Scanning'],
    'TOOL_METASPLOIT'     => ['T1588.002', 'Obtain Capabilities: Tool'],
    'TOOL_HYDRA'          => ['T1110', 'Brute Force'],
    'TOOL_MASSCAN'        => ['T1595.001', 'Scanning IP Blocks'],
    'TOOL_NMAP'           => ['T1046', 'Network Service Discovery'],
];

function sb_write_event(array $event): void
{
    // Tagged here rather than at each call site, so the two dozen places that
    // write events cannot drift from each other. Events with no corresponding
    // technique are left untagged: an HTTP request is not an ATT&CK technique,
    // and mapping everything would make the chart describe this table instead
    // of the traffic.
    $type = (string)($event['event_type'] ?? '');
    if (isset(TECHNIQUES[$type])) {
        [$event['technique_id'], $event['technique']] = TECHNIQUES[$type];
    }

    sb_append_line(
        STORAGE_PATH . '/logs/' . gmdate('Y-m-d') . '.jsonl',
        json_encode($event, JSON_UNESCAPED_SLASHES) . "\n"
    );
}

// ------------------------------------------------------------- session camera

function sb_write_atomic(string $path, string $content): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }
    // tmp-then-rename so session-cam never reads a half-written sidecar.
    $tmp = $path . '.tmp';
    if (@file_put_contents($tmp, $content) === false) {
        return;
    }
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
    }
}

/**
 * Append one webshell exchange to an asciicast recording, as a shell prompt.
 *
 * Recording only. Nothing here executes, and the command is written as text.
 */
function sb_cam_record(string $ip, string $command, string $output): void
{
    sb_cam_append($ip, static function (array $identity) use ($command, $output): array {
        $hostname = (string)($identity['fake_hostname'] ?? 'srv-01');
        $cwd = (string)($identity['fake_cwd'] ?? '/var/www/html');
        $prompt = 'www-data@' . $hostname . ':' . $cwd . '$ ';
        $frames = [$prompt . $command . "\r\n"];
        // Terminals need CRLF; the simulated output uses bare LF.
        $rendered = str_replace("\n", "\r\n", $output);
        if ($rendered !== '') {
            $frames[] = $rendered . "\r\n";
        }
        return $frames;
    });
}

/**
 * Record HTTP activity that is not a webshell command.
 *
 * Scanner path hits and tarpit drips were scored, alerted and logged, but they
 * were the one kind of attacker traffic with no recording -- so the live feed
 * and evidence bundles showed webshell sessions and nothing else, even though
 * probes and tarpits are the overwhelming majority of what arrives. They share
 * a cast with the webshell because they are the same address over the same
 * protocol; one recording per IP is the session that actually happened.
 */
function sb_cam_http(string $ip, string $line, string $detail = ''): void
{
    if (!CAM_RECORD_WEB_PROBES) {
        return;
    }
    sb_cam_append($ip, static function (array $identity) use ($line, $detail): array {
        $frames = [$line . "\r\n"];
        if ($detail !== '') {
            $frames[] = '    ' . str_replace("\n", "\r\n    ", $detail) . "\r\n";
        }
        return $frames;
    });
}

/**
 * Append frames to this IP's web recording, opening one if needed.
 *
 * HTTP is stateless: there is no socket whose close can end a recording the way
 * it does for SSH or telnet. So everything one IP does over HTTP is grouped
 * into a single .cast for as long as it keeps arriving inside the idle window,
 * and the sidecar carries an `open_until` deadline telling session-cam when the
 * recording has been quiet long enough to be safe to render.
 *
 * `$build` receives the freshly read identity and returns the frame texts. It
 * is a callback rather than an array so callers that need the identity -- for a
 * shell prompt, say -- do not have to read it a second time, and so the read
 * still happens after scoring, which is what makes the clip carry the score the
 * command earned rather than the one before it.
 */
function sb_cam_append(string $ip, callable $build): void
{
    if (!sb_storage_ok()) {
        return;
    }

    // Read back rather than taking the caller's copy: scoring has already run
    // for this command, so this picks up the score the clip should be captioned
    // with instead of the one from before the command.
    $identity = get_or_create_identity($ip);
    $frames = $build($identity);
    if (!$frames) {
        return;
    }
    $redis = sb_redis();
    $key = 'hp:cam:' . sb_ip_hash($ip);
    $state = null;

    if ($redis->isReady()) {
        $raw = $redis->get($key);
        if (is_string($raw) && $raw !== '') {
            $decoded = json_decode($raw, true);
            if (is_array($decoded) && isset($decoded['stem'], $decoded['started'])) {
                $state = $decoded;
            }
        }
    }

    if ($state === null) {
        // With Redis down, bucket by the idle window so consecutive commands
        // still group into one recording rather than one file per request.
        $started = $redis->isReady()
            ? time()
            : (int)floor(time() / CAM_WEB_IDLE_SECONDS) * CAM_WEB_IDLE_SECONDS;
        $state = [
            'stem' => str_replace([':', '/'], '_', $ip) . '_'
                      . gmdate('Ymd\THis', $started) . '_web',
            'started' => $started,
            'frames' => 0,
        ];
    }

    $cast = STORAGE_PATH . '/sessions/' . $state['stem'] . '.cast';

    if (!is_file($cast)) {
        sb_append_line($cast, json_encode([
            'version' => 2,
            'width' => 100,
            'height' => 30,
            'timestamp' => (int)$state['started'],
            'title' => 'webshell session from ' . $ip,
            'env' => ['SHELL' => '/bin/sh', 'TERM' => 'xterm-256color'],
        ], JSON_UNESCAPED_SLASHES) . "\n");
    }

    $size = @filesize($cast);
    if ($size !== false && $size > CAM_MAX_SESSION_BYTES) {
        sb_cam_meta($ip, $identity, $state, $cast, true);
        return;
    }

    $offset = max(0, time() - (int)$state['started']);
    foreach (array_values($frames) as $index => $text) {
        sb_append_line($cast, json_encode(
            [$offset + $index * 0.05, 'o', $text], JSON_UNESCAPED_SLASHES
        ) . "\n");
    }

    $state['frames'] = (int)($state['frames'] ?? 0) + count($frames);
    if ($redis->isReady()) {
        $redis->setex($key, CAM_WEB_IDLE_SECONDS, json_encode($state));
    }
    sb_cam_meta($ip, $identity, $state, $cast, false);
}

function sb_cam_meta(string $ip, array $identity, array $state, string $cast,
                     bool $truncated): void
{
    $credentials = [];
    foreach (array_slice((array)($identity['credentials'] ?? []), -10) as $entry) {
        $credentials[] = ($entry['username'] ?? '') . ':' . ($entry['password'] ?? '');
    }

    $size = @filesize($cast);
    sb_write_atomic(
        STORAGE_PATH . '/sessions/' . $state['stem'] . '.meta.json',
        json_encode([
            'version' => 1,
            'cast' => $state['stem'] . '.cast',
            'ip' => $ip,
            'service' => 'web',
            'title' => 'webshell session from ' . $ip,
            'width' => 100,
            'height' => 30,
            'started_at' => gmdate('c', (int)$state['started']),
            'duration' => max(0, time() - (int)$state['started']),
            'frames' => (int)($state['frames'] ?? 0),
            'bytes' => $size === false ? 0 : $size,
            'truncated' => $truncated,
            // Only render once the attacker has stopped typing for this long --
            // an HTTP webshell has no connection close to signal the end.
            'open_until' => time() + CAM_WEB_IDLE_SECONDS,
            'score' => (float)($identity['score'] ?? 0),
            'tool' => (string)($identity['tool_detected'] ?? ''),
            'services_touched' => array_values((array)($identity['services_touched'] ?? [])),
            'fake_hostname' => (string)($identity['fake_hostname'] ?? ''),
            'banned' => (bool)($identity['banned'] ?? false),
            'tarpit_active' => (bool)($identity['tarpit_active'] ?? false),
            'credentials' => $credentials,
        ], JSON_UNESCAPED_SLASHES)
    );
}

function sb_request_headers(): array
{
    $keep = [
        'HTTP_USER_AGENT' => 'user_agent',
        'HTTP_REFERER' => 'referer',
        'HTTP_CF_CONNECTING_IP' => 'cf_connecting_ip',
        'HTTP_CF_IPCOUNTRY' => 'cf_ipcountry',
        'HTTP_CF_RAY' => 'cf_ray',
        'HTTP_X_REAL_IP' => 'x_real_ip',
        'HTTP_ACCEPT_LANGUAGE' => 'accept_language',
        'HTTP_HOST' => 'host',
    ];
    $out = [];
    foreach ($keep as $server => $name) {
        if (!empty($_SERVER[$server])) {
            $out[$name] = mb_substr((string)$_SERVER[$server], 0, 300);
        }
    }
    return $out;
}

function log_request(string $ip, array $extra = []): void
{
    // Health checks are not traffic worth keeping. Left in, they were the
    // HTTP_REQUEST lines filling the gateway's event log and inflating every
    // per-day request count with the appliance polling itself.
    if (sb_is_ignored($ip)) {
        return;
    }

    $postKeys = array_map(static fn($k) => mb_substr((string)$k, 0, 64), array_keys($_POST));
    $payload = '';
    if (!empty($_POST)) {
        $encoded = json_encode($_POST, JSON_UNESCAPED_SLASHES);
        $payload = mb_substr((string)$encoded, 0, MAX_LOG_VALUE);
        if (strlen((string)$encoded) > MAX_LOG_VALUE) {
            $payload .= sprintf(' [TRUNCATED: %d bytes]', strlen((string)$encoded));
        }
    }

    sb_write_event(array_merge([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => 'HTTP_REQUEST',
        'uri' => mb_substr((string)($_SERVER['REQUEST_URI'] ?? '/'), 0, 500),
        'method' => (string)($_SERVER['REQUEST_METHOD'] ?? 'GET'),
        'payload_excerpt' => $payload,
        'post_keys' => $postKeys,
        'headers' => sb_request_headers(),
    ], $extra));
}

// -------------------------------------------------------------- rate limiting

/** Sliding-window rate limit backed by a Redis sorted set. */
function sb_rate_limited(string $ip): bool
{
    $redis = sb_redis();
    if (!$redis->isReady()) {
        return false;
    }
    $key = 'hp:rate:' . sb_ip_hash($ip);
    $now = microtime(true);

    $redis->zremrangebyscore($key, '-inf', (string)($now - 60));
    $redis->zadd($key, $now, sprintf('%.6f-%s', $now, bin2hex(random_bytes(4))));
    $redis->expire($key, 120);

    return $redis->zcard($key) > RATE_LIMIT_RPM;
}

// -------------------------------------------------------------- tool detection

/** userAgent needle => [event, label, tarpit immediately] */
const TOOL_SIGNATURES = [
    'sqlmap'          => ['TOOL_SQLMAP', 'sqlmap', true],
    'nikto'           => ['TOOL_NIKTO', 'Nikto', true],
    'nuclei'          => ['TOOL_NUCLEI', 'Nuclei', true],
    'masscan'         => ['TOOL_MASSCAN', 'Masscan', true],
    'metasploit'      => ['TOOL_METASPLOIT', 'Metasploit', true],
    'feroxbuster'     => ['TOOL_OTHER', 'feroxbuster', true],
    'ffuf'            => ['TOOL_OTHER', 'ffuf', true],
    'gobuster'        => ['TOOL_OTHER', 'gobuster', true],
    'dirbuster'       => ['TOOL_OTHER', 'DirBuster', true],
    'dirsearch'       => ['TOOL_OTHER', 'dirsearch', true],
    'wfuzz'           => ['TOOL_OTHER', 'wfuzz', true],
    'acunetix'        => ['TOOL_OTHER', 'Acunetix', true],
    'nessus'          => ['TOOL_OTHER', 'Nessus', true],
    'openvas'         => ['TOOL_OTHER', 'OpenVAS', true],
    'zgrab'           => ['TOOL_OTHER', 'zgrab', true],
    'wapiti'          => ['TOOL_OTHER', 'Wapiti', true],
    'w3af'            => ['TOOL_OTHER', 'w3af', true],
    'wpscan'          => ['TOOL_OTHER', 'WPScan', true],
    'python-requests' => ['TOOL_OTHER', 'python-requests', false],
    'go-http-client'  => ['TOOL_OTHER', 'Go HTTP client', false],
];

/** @return array{0:string,1:string,2:bool}|null */
function detect_tool(string $userAgent): ?array
{
    $needle = strtolower($userAgent);
    foreach (TOOL_SIGNATURES as $signature => $meta) {
        if (str_contains($needle, $signature)) {
            return $meta;
        }
    }
    return null;
}

// --------------------------------------------------------------- tarpit engine

/**
 * What a banned address gets. Never returns.
 *
 * A 302 is only a rickroll to something that follows redirects, and the clients
 * that earn a ban here largely do not: curl-based scanners and `SSH-2.0-Go`
 * worms read the status line and move on. So anything that did not ask for HTML
 * gets the art as text/plain instead, dripped, out of the same
 * `shared/rickroll.txt` the SSH and telnet services read. Real browsers still
 * get the video.
 *
 * The drip takes a tarpit concurrency slot. Without one this would be an
 * uncapped way to pin a PHP-FPM worker for two minutes, which is precisely the
 * thing TARPIT_MAX_CONCURRENT exists to prevent; a banned flood would starve
 * the pool that the rest of the site needs.
 */
function sb_rickroll(string $ip): void
{
    $art = (RICKROLL_ENABLED && is_readable(RICKROLL_FILE))
        ? @file_get_contents(RICKROLL_FILE)
        : false;
    $wantsHtml = stripos((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html') !== false;

    // A browser, a disabled rickroll, or a missing bind mount. The fallback is
    // deliberate: losing the mount should cost the joke, not the ban.
    if ($art === false || $art === '' || $wantsHtml) {
        header('Location: ' . RICKROLL_URL, true, 302);
        exit;
    }

    $redis = sb_redis();
    $counterKey = 'hp:tarpit:concurrent';
    $slotTaken = false;
    if ($redis->isReady()) {
        $active = (int)$redis->incr($counterKey);
        $redis->expire($counterKey, TARPIT_MAX_SECONDS + 60);
        if ($active > TARPIT_MAX_CONCURRENT) {
            $redis->decr($counterKey);
            header('Location: ' . RICKROLL_URL, true, 302);
            exit;
        }
        $slotTaken = true;
    }
    register_shutdown_function(static function () use ($redis, $counterKey, &$slotTaken): void {
        if ($slotTaken && $redis->isReady()) {
            $redis->decr($counterKey);
            $slotTaken = false;
        }
    });

    @ignore_user_abort(false);
    @set_time_limit(0);
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    http_response_code(200);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Content-Length: ' . strlen($art));
    header('Cache-Control: no-cache');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    header('X-Accel-Buffering: no');

    // Paced across the window rather than sent at once. Content-Length promises
    // the rest, so a client waiting for a complete body waits for all of it.
    // A line at a time: byte-at-a-time through php-fpm and nginx buys nothing
    // over a line, and costs a flush per byte.
    $lines = preg_split("/(?<=\n)/", $art, -1, PREG_SPLIT_NO_EMPTY);
    if (!$lines) {
        $lines = [$art];
    }
    $delay = (int)(RICKROLL_DRIP_SECONDS * 1000000 / max(count($lines), 1));
    $deadline = microtime(true) + RICKROLL_DRIP_SECONDS;
    $started = time();

    foreach ($lines as $index => $line) {
        echo $line;
        @flush();
        if (connection_aborted()) {
            break;
        }
        if (microtime(true) >= $deadline) {
            // Flush the remainder rather than leave a body short of its
            // Content-Length, which is the one thing that would make this
            // look broken rather than slow.
            echo implode('', array_slice($lines, $index + 1));
            @flush();
            break;
        }
        usleep($delay);
    }

    sb_log_tarpit($ip, 'banned rickroll', time() - $started, count($lines));
    exit;
}

/**
 * Hold the attacker's connection open, trickling plausible page content.
 *
 * Zero-trust: this executes nothing. It exists only to consume the scanner's
 * connection slot and thread. Bounded by TARPIT_MAX_SECONDS and a global
 * concurrency cap so it can never exhaust our own PHP-FPM pool.
 */
function run_tarpit(string $ip, string $reason): void
{
    $redis = sb_redis();
    $counterKey = 'hp:tarpit:concurrent';
    $slotTaken = false;

    if ($redis->isReady()) {
        $active = (int)$redis->incr($counterKey);
        $redis->expire($counterKey, TARPIT_MAX_SECONDS + 60);
        if ($active > TARPIT_MAX_CONCURRENT) {
            // Pool protection: shed this one rather than starving real capacity.
            $redis->decr($counterKey);
            http_response_code(404);
            header('Content-Type: text/html; charset=UTF-8');
            echo "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>"
                . "<h1>Not Found</h1></body></html>";
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
    header('Content-Type: text/html; charset=UTF-8');
    header('Content-Length: 10485760');
    header('Cache-Control: no-cache');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    header('X-Accel-Buffering: no');

    $started = time();
    $deadline = $started + TARPIT_MAX_SECONDS;

    // Register this hold for as long as it runs, so the dashboard can show the
    // connection being drained rather than only reporting it afterwards. The
    // HTTP tarpit is the longest-running one in the appliance -- up to 15
    // minutes against a browser or scraper -- so it is the one most worth
    // seeing live. TTL outlives the maximum hold, so a worker killed
    // mid-drain cannot leave a phantom connection on the dashboard.
    $holdKey = 'hp:holding:' . sb_ip_hash($ip) . ':web:' . getmypid() . ':' . $started;
    $redisHold = sb_redis();
    if ($redisHold->isReady()) {
        $redisHold->setex($holdKey, TARPIT_MAX_SECONDS + 30, json_encode([
            'ip' => $ip,
            'service' => 'web',
            'started' => $started,
        ]));
    }
    $releaseHold = static function () use ($redisHold, $holdKey): void {
        if ($redisHold->isReady()) {
            $redisHold->del($holdKey);
        }
    };

    // Recorded as well as held, so the drip can be watched on the live feed
    // while it is happening rather than only counted after it ends.
    sb_cam_http($ip,
        sprintf('--- tarpit engaged: %s ---', $reason),
        sprintf('%s %s', $_SERVER['REQUEST_METHOD'] ?? 'GET',
                substr((string)($_SERVER['REQUEST_URI'] ?? '/'), 0, 200)));

    $preamble = [
        "<!DOCTYPE html><html><head><title>" . sb_html(COMPANY_NAME) . "</title>",
        "<meta charset='UTF-8'><meta name='generator' content='WordPress 6.4.3'>",
        "<style>body{font-family:sans-serif;color:#333}</style></head><body>",
        "<header><h1>" . sb_html(COMPANY_NAME) . "</h1></header><main>",
    ];
    foreach ($preamble as $chunk) {
        if (connection_aborted()) {
            sb_log_tarpit($ip, $reason, time() - $started, 0);
            sb_cam_http($ip, sprintf(
                '--- tarpit released after %ds, client gave up during preamble ---',
                time() - $started));
            $releaseHold();
            $release();
            exit;
        }
        echo $chunk;
        @flush();
        usleep(TARPIT_CHUNK_DELAY_US);
    }

    $words = ['cloud', 'security', 'enterprise', 'digital', 'transformation',
              'infrastructure', 'scalable', 'solution', 'managed', 'service',
              'platform', 'integration', 'compliance', 'resilience'];
    $counter = 0;

    while (!connection_aborted() && time() < $deadline) {
        $paragraph = '<p class="content-' . $counter . '">';
        for ($i = 0; $i < 20; $i++) {
            $paragraph .= $words[array_rand($words)] . ' ';
        }
        $paragraph .= "</p>\n";

        echo $paragraph;
        @flush();
        usleep(TARPIT_CHUNK_DELAY_US);
        $counter++;

        if ($counter % 200 === 0) {
            sb_log_tarpit($ip, $reason, time() - $started, $counter, 'TARPIT_KEEPALIVE');
            // Same cadence as the keepalive rather than per chunk: a frame
            // every few hundred milliseconds for fifteen minutes would be a
            // large file recording nothing but the passage of time.
            sb_cam_http($ip, sprintf('    ... still holding, %ds, %d chunks sent',
                                     time() - $started, $counter));
        }
    }

    sb_log_tarpit($ip, $reason, time() - $started, $counter);
    sb_cam_http($ip, sprintf('--- tarpit released after %ds (%d chunks%s) ---',
                             time() - $started, $counter,
                             connection_aborted() ? ', client gave up' : ''));
    $releaseHold();
    $release();
    exit;
}

function sb_log_tarpit(string $ip, string $reason, int $seconds, int $chunks,
                       string $eventType = 'TARPIT_HELD'): void
{
    sb_write_event([
        'timestamp' => gmdate('c'),
        'real_ip' => $ip,
        'service' => 'web',
        'event_type' => $eventType,
        'reason' => $reason,
        'held_seconds' => $seconds,
        'chunks_sent' => $chunks,
        'tarpit_active' => true,
        'headers' => sb_request_headers(),
    ]);
}

// ---------------------------------------------------------------- bootstrap

/**
 * Runs at the top of every public entry point.
 *
 * Returns the resolved IP and identity. Bans redirect, rate-limit abuse and
 * active tarpits never return.
 */
function sb_bootstrap(): array
{
    $ip = get_real_ip();

    if (is_banned($ip)) {
        sb_rickroll($ip);
    }

    if (sb_rate_limited($ip)) {
        score_event($ip, 'RATE_LIMIT_ABUSE', 'rate limit exceeded');
        activate_tarpit($ip, 'Rate limit exceeded');
        sleep(5);
        run_tarpit($ip, 'Rate limit exceeded');
    }

    $identity = get_or_create_identity($ip);
    $userAgent = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');

    $tool = detect_tool($userAgent);
    if ($tool !== null) {
        [$event, $label, $immediate] = $tool;
        if (($identity['tool_detected'] ?? null) !== $label) {
            score_event($ip, $event, $userAgent, $label);
            $identity = get_or_create_identity($ip);
        }
        if ($immediate) {
            activate_tarpit($ip, "$label detected in User-Agent");
            run_tarpit($ip, "$label detected");
        }
    }

    if (!empty($identity['tarpit_active'])) {
        run_tarpit($ip, 'IP flagged for tarpit');
    }

    return [$ip, $identity];
}

function sb_html(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
