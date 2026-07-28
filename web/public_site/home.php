<?php
declare(strict_types=1);

/*
 * The public homepage.
 *
 * index.html is a template rather than the served page: the company name,
 * address and honeytoken credentials in it belong to this deployment's persona,
 * and a name published in this repository identifies any host still using it.
 * nginx routes `/` here and sends a direct request for /index.html to the
 * scanner trap, so the template itself is never served with its placeholders
 * showing.
 *
 * Rendering only. Nothing here scores or bans: the homepage is the one URL a
 * legitimate visitor or crawler is expected to fetch.
 */

require_once __DIR__ . '/../lib/drosera.php';

$template = @file_get_contents(__DIR__ . '/index.html');

if ($template === false) {
    // Never show a PHP error to a visitor -- an error page on the front door
    // is the loudest possible tell.
    http_response_code(503);
    header('Content-Type: text/html; charset=UTF-8');
    header('Retry-After: 120');
    echo '<!DOCTYPE html><html><head><title>Service Unavailable</title></head>'
        . '<body><h1>Service Unavailable</h1>'
        . '<p>The server is temporarily unable to service your request. '
        . 'Please try again later.</p></body></html>';
    exit;
}

$replacements = [
    '{{COMPANY_NAME}}'     => sb_html(COMPANY_NAME),
    '{{COMPANY_SHORT}}'    => sb_html(COMPANY_SHORT),
    '{{COMPANY_INITIALS}}' => sb_html(sb_company_initials()),
    '{{COMPANY_ADDRESS}}'  => sb_html(COMPANY_ADDRESS),
    '{{COMPANY_DOMAIN}}'   => sb_html(COMPANY_DOMAIN),
    '{{COMPANY_FOUNDED}}'  => (string)COMPANY_FOUNDED,
    // Honeytokens. Nothing accepts them, so their appearance anywhere else is
    // evidence of where they were scraped from -- provided they are unique to
    // this deployment.
    '{{HONEYTOKEN_KEY}}'   => sb_html(FAKE_HONEYTOKEN_KEY),
    '{{DB_USER}}'          => sb_html(FAKE_DB_USER),
    '{{DB_PASSWORD}}'      => sb_html(FAKE_DB_PASSWORD),
    '{{DB_NAME}}'          => sb_html(FAKE_DB_NAME),
    '{{STAGING_IP}}'       => sb_html(FAKE_STAGING_IP),
    '{{MAIL_PASSWORD}}'    => sb_html(FAKE_MAIL_PASSWORD),
];

header('Content-Type: text/html; charset=UTF-8');
header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);

echo strtr($template, $replacements);
