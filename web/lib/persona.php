<?php
declare(strict_types=1);

/*
 * Per-deployment identity, PHP side.
 *
 * The Python honeypots read the same /persona/persona.json through
 * shared/persona.py. Both must agree: an attacker who sees Apache 2.4.41 in an
 * HTTP header and a different server string in the fake shell has found the
 * seam between the two halves of the machine.
 *
 * Absent the file, the defaults below apply and a fresh clone runs. They are
 * published in this repository, which is exactly why a real deployment
 * generates its own:
 *
 *     ./deploy/generate-persona.sh
 */

/**
 * Read one persona value, falling back to the published default.
 *
 * Loads the file once per request. Failure is never fatal: a malformed persona
 * degrades to the defaults rather than taking the site down and revealing it.
 */
function sb_persona(string $key, $default = null)
{
    static $loaded = null;

    if ($loaded === null) {
        $loaded = [];
        $path = getenv('PERSONA_FILE') ?: '/persona/persona.json';
        if (is_readable($path)) {
            $raw = @file_get_contents($path);
            if ($raw !== false) {
                $data = json_decode($raw, true);
                if (is_array($data)) {
                    $loaded = $data;
                }
            }
        }
    }

    if (isset($loaded[$key]) && $loaded[$key] !== '' && $loaded[$key] !== []) {
        return $loaded[$key];
    }

    static $defaults = [
        'http_server'     => 'Apache/2.4.41 (Ubuntu)',
        'php_version'     => '7.4.33',
        'mysql_version'   => '5.7.38-0ubuntu0.22.04.1',
        'company_name'    => 'Meridian Digital Solutions',
        'company_short'   => 'Meridian Digital',
        'company_address' => '847 Commerce Drive, Suite 210, Austin, TX 78701',
        'company_founded' => 2019,
        // 555-01xx is the block reserved for fiction; the area code matches the
        // fallback address above.
        'company_phone'   => '(512) 555-0123',
        'company_entity'  => 'LLC',
        'company_tagline' => 'Expert IT Solutions for Modern Business',
        'company_keywords' => 'IT consulting, managed services, infrastructure',
        'company_domain'  => 'meridiandigital.example',
        'company_slug'    => 'meridian',
        'db_name'         => 'meridian_prod',
        'db_user'         => 'devuser',
        'db_password'     => 'DevPass2024!',
        'honeytoken_key'  => 'sk-mrd-test-4f8a2c1b9e3d7f6a',
        'aws_access_key_id' => 'AKIA4MRDN2QX7VLPWZ3T',
        'aws_access_key_id_staging' => 'AKIA4MRDN2QXHK9DLM2P',
        'mail_password'   => 'Staging#Pass99',
        'staging_ip'      => '10.0.1.47',
        'last_login_from' => '10.0.1.9',
        'user_pool'       => [
            ['jmarsh', '/home/jmarsh'], ['dkowalski', '/home/dkowalski'],
            ['rchen', '/home/rchen'],
        ],
        'seeded_history'  => [
            'cd /var/www/html', 'ls -la', 'tail -f /var/log/nginx/error.log',
            'systemctl restart php7.4-fpm', 'mysql -u devuser -p meridian_prod',
            'df -h', 'sudo apt-get update', 'vim wp-config.php',
        ],
    ];

    if (array_key_exists($key, $defaults)) {
        return $defaults[$key];
    }
    return $default;
}

/**
 * The site's wordmark: first word plain, the rest in a highlight span.
 *
 * "Meridian Digital" renders as Meridian<span>Digital</span>, which is what the
 * stylesheet expects regardless of the words the persona picked.
 */
function sb_company_logo(): string
{
    $parts = explode(' ', (string)sb_persona('company_short'), 2);
    $head = sb_html($parts[0]);
    if (count($parts) < 2) {
        return $head;
    }
    return $head . '<span>' . sb_html($parts[1]) . '</span>';
}

/** Initials for the favicon wordmark: "Meridian Digital" -> "MD". */
function sb_company_initials(): string
{
    $words = preg_split('/\s+/', trim((string)sb_persona('company_short'))) ?: [];
    $initials = '';
    foreach ($words as $word) {
        if ($word !== '') {
            $initials .= strtoupper($word[0]);
        }
    }
    return substr($initials, 0, 3) ?: 'CO';
}

/** Short uppercase prefix for ticket/reference numbers, e.g. "MRD". */
function sb_company_ref(): string
{
    $slug = preg_replace('/[^a-z]/', '', strtolower((string)sb_persona('company_slug')));
    $slug = (string)$slug;
    if (strlen($slug) < 3) {
        return 'REF';
    }
    // Consonant skeleton reads like a real abbreviation: meridian -> MRD.
    $skeleton = preg_replace('/[aeiou]/', '', substr($slug, 1));
    $abbrev = strtoupper(substr($slug, 0, 1) . (string)$skeleton);
    return substr(str_pad($abbrev, 3, strtoupper($slug)), 0, 3);
}

/** True when a generated persona is in use rather than the public defaults. */
function sb_persona_is_custom(): bool
{
    $path = getenv('PERSONA_FILE') ?: '/persona/persona.json';
    return is_readable($path);
}
