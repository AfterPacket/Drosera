<?php
declare(strict_types=1);

/*
 * XML sitemap.
 *
 * Generated rather than static so the URLs match whatever domain is actually
 * attached. A sitemap advertising a different hostname than the one being
 * served is an obvious tell, and crawlers would ignore the entries entirely.
 *
 * Most entries point into /blog/, which is the infinite crawler trap: a
 * crawler that honours the sitemap walks straight into it.
 */

require_once __DIR__ . '/../lib/drosera.php';

// Sitemap fetches are ordinary crawler behaviour, so this is logged but not
// scored. Bans and active tarpits still apply via the bootstrap.
[$ip, $identity] = sb_bootstrap();
log_request($ip, ['handler' => 'sitemap']);

$host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
// Host is attacker-controlled; allow only what can legitimately appear here.
if (!preg_match('/^[A-Za-z0-9.\-]{1,253}(:\d{1,5})?$/', $host)) {
    $host = 'localhost';
}
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
    ? 'https' : 'http';
$base = $scheme . '://' . $host;

$pages = [
    ['/',                              '1.0', 'weekly',  '-2 days'],
    ['/#services',                     '0.9', 'monthly', '-9 days'],
    ['/#about',                        '0.7', 'monthly', '-21 days'],
    ['/#portfolio',                    '0.7', 'monthly', '-16 days'],
    ['/#contact',                      '0.8', 'monthly', '-11 days'],
    ['/blog/',                         '0.9', 'daily',   '-1 day'],
    ['/blog/cloud-migration-2024',     '0.8', 'monthly', '-40 days'],
    ['/blog/zero-trust-architecture',  '0.8', 'monthly', '-53 days'],
    ['/blog/wordpress-security',       '0.8', 'monthly', '-66 days'],
    ['/blog/managed-service-levels',   '0.6', 'monthly', '-74 days'],
    ['/blog/incident-response-runbook', '0.6', 'monthly', '-88 days'],
    ['/blog/backup-strategy-2024',     '0.6', 'monthly', '-95 days'],
    ['/blog/container-orchestration',  '0.6', 'monthly', '-110 days'],
    ['/blog/least-privilege-in-practice', '0.6', 'monthly', '-124 days'],
    ['/blog/observability-basics',     '0.6', 'monthly', '-138 days'],
];

header('Content-Type: application/xml; charset=UTF-8');
header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);

echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";
foreach ($pages as [$path, $priority, $frequency, $age]) {
    printf(
        "    <url>\n        <loc>%s</loc>\n        <lastmod>%s</lastmod>\n"
        . "        <changefreq>%s</changefreq>\n        <priority>%s</priority>\n    </url>\n",
        sb_html($base . $path),
        gmdate('Y-m-d', strtotime($age) ?: time()),
        $frequency,
        $priority
    );
}
echo '</urlset>' . "\n";
