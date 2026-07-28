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
define('RICKROLL_URL', getenv('RICKROLL_URL') ?: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');

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
    'TOOL_OTHER'          => [2,  'Automated scanner detected'],
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

function get_or_create_identity(string $ip): array
{
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

    $redis = sb_redis();
    if ($redis->isReady()) {
        $redis->setex(sb_identity_key($ip), IDENTITY_TTL, json_encode($identity));
    }
    return $identity;
}

function is_tarpitted(string $ip): bool
{
    return !empty(get_or_create_identity($ip)['tarpit_active']);
}

function is_banned(string $ip): bool
{
    $redis = sb_redis();
    return $redis->isReady() && $redis->exists('hp:banned:' . sb_ip_hash($ip)) > 0;
}

function activate_tarpit(string $ip, string $reason = 'Threshold reached'): void
{
    $identity = get_or_create_identity($ip);
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

/**
 * Apply points to an IP, append to its history, and escalate to tarpit/ban.
 */
function score_event(string $ip, string $eventType, string $payload = '', string $tool = ''): array
{
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
    if ($new >= TARPIT_THRESHOLD) {
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

    if ($new >= BAN_THRESHOLD && empty($identity['banned'])) {
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

function sb_write_event(array $event): void
{
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
 * Append one webshell exchange to an asciicast recording.
 *
 * The webshell is stateless HTTP: there is no socket whose close can end a
 * recording the way it does for SSH or telnet. So commands from one IP are
 * grouped into a single .cast for as long as they keep arriving inside the idle
 * window, and the sidecar carries an `open_until` deadline telling session-cam
 * when the recording has been quiet long enough to be safe to render.
 *
 * Recording only. Nothing here executes, and the command is written as text.
 */
function sb_cam_record(string $ip, string $command, string $output): void
{
    if (!sb_storage_ok()) {
        return;
    }

    // Read back rather than taking the caller's copy: scoring has already run
    // for this command, so this picks up the score the clip should be captioned
    // with instead of the one from before the command.
    $identity = get_or_create_identity($ip);
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
    $hostname = (string)($identity['fake_hostname'] ?? 'srv-01');
    $cwd = (string)($identity['fake_cwd'] ?? '/var/www/html');

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
    $prompt = 'www-data@' . $hostname . ':' . $cwd . '$ ';
    // Terminals need CRLF; the simulated output uses bare LF.
    $rendered = str_replace("\n", "\r\n", $output);

    sb_append_line($cast, json_encode(
        [$offset, 'o', $prompt . $command . "\r\n"], JSON_UNESCAPED_SLASHES
    ) . "\n");
    if ($rendered !== '') {
        sb_append_line($cast, json_encode(
            [$offset + 0.05, 'o', $rendered . "\r\n"], JSON_UNESCAPED_SLASHES
        ) . "\n");
    }

    $state['frames'] = (int)($state['frames'] ?? 0) + ($rendered !== '' ? 2 : 1);
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

    $preamble = [
        "<!DOCTYPE html><html><head><title>" . sb_html(COMPANY_NAME) . "</title>",
        "<meta charset='UTF-8'><meta name='generator' content='WordPress 6.4.3'>",
        "<style>body{font-family:sans-serif;color:#333}</style></head><body>",
        "<header><h1>" . sb_html(COMPANY_NAME) . "</h1></header><main>",
    ];
    foreach ($preamble as $chunk) {
        if (connection_aborted()) {
            sb_log_tarpit($ip, $reason, time() - $started, 0);
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
        }
    }

    sb_log_tarpit($ip, $reason, time() - $started, $counter);
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
        header('Location: ' . RICKROLL_URL, true, 302);
        exit;
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
