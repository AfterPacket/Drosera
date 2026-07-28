<?php
declare(strict_types=1);

/*
 * WordPress XML-RPC endpoint replica.
 *
 * XML-RPC is a favourite brute-force amplifier: system.multicall lets an
 * attacker try hundreds of credentials in one request. We parse the method name
 * and count embedded logins for scoring, then return a plausible response.
 *
 * Zero-trust: the request body is read as text and pattern-matched. It is never
 * parsed into an executable structure, and no XML external entities are resolved.
 */

require_once __DIR__ . '/../lib/drosera.php';

[$ip, $identity] = sb_bootstrap();

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$body = '';
if ($method === 'POST') {
    $raw = file_get_contents('php://input', false, null, 0, 262144);
    $body = $raw === false ? '' : $raw;
}

log_request($ip, ['handler' => 'xmlrpc', 'body_excerpt' => mb_substr($body, 0, MAX_LOG_VALUE)]);
score_event($ip, 'SCANNER_PATH_HIT', '/xmlrpc.php');

sb_write_event([
    'timestamp' => gmdate('c'),
    'real_ip' => $ip,
    'service' => 'web',
    'event_type' => 'XMLRPC_REQUEST',
    'method' => $method,
    'payload_excerpt' => mb_substr($body, 0, 500),
    'body_bytes' => strlen($body),
    'headers' => sb_request_headers(),
]);

if ($method === 'GET') {
    header('Content-Type: text/plain; charset=UTF-8');
    header('Allow: POST');
    http_response_code(405);
    echo "XML-RPC server accepts POST requests only.";
    exit;
}

// Extract the requested method name without building an XML parse tree.
$methodName = '';
if (preg_match('#<methodName>\s*([A-Za-z0-9._]{1,64})\s*</methodName>#', $body, $m)) {
    $methodName = $m[1];
}

// system.multicall is the brute-force amplification vector.
if (strcasecmp($methodName, 'system.multicall') === 0) {
    $loginCount = preg_match_all('#<methodName>\s*wp\.[A-Za-z]+\s*</methodName>#i', $body);
    $loginCount = $loginCount === false ? 0 : $loginCount;

    score_event($ip, 'CREDENTIAL_SPRAY', "system.multicall with {$loginCount} calls");
    activate_tarpit($ip, 'XML-RPC system.multicall brute force');

    // Capture the credential pairs carried in the multicall.
    if (preg_match_all('#<string>([^<]{0,128})</string>#', $body, $matches)) {
        $values = array_slice($matches[1], 0, 40);
        sb_write_event([
            'timestamp' => gmdate('c'),
            'real_ip' => $ip,
            'service' => 'web',
            'event_type' => 'XMLRPC_CREDENTIALS',
            'reason' => 'Credentials carried in system.multicall',
            'payload_excerpt' => mb_substr(implode(' | ', $values), 0, 500),
            'call_count' => $loginCount,
        ]);
    }

    respond_fault(403, 'Incorrect username or password.');
}

// Direct wp.* login attempts carry <value><string>user</string></value> pairs.
if (stripos($methodName, 'wp.') === 0 || stripos($methodName, 'metaWeblog.') === 0) {
    if (preg_match_all('#<string>([^<]{0,128})</string>#', $body, $matches)
        && count($matches[1]) >= 2) {
        $username = $matches[1][count($matches[1]) - 2];
        $password = $matches[1][count($matches[1]) - 1];
        score_event($ip, 'CREDENTIAL_ATTEMPT', "{$username}:{$password}");
    }
    respond_fault(403, 'Incorrect username or password.');
}

if (strcasecmp($methodName, 'pingback.ping') === 0) {
    // Pingback is an SSRF vector on real WordPress. Refuse it convincingly.
    score_event($ip, 'SQLI_OOB', 'pingback.ping SSRF attempt');
    respond_fault(0, 'The pingback has already been registered.');
}

if (strcasecmp($methodName, 'system.listMethods') === 0) {
    $methods = ['system.multicall', 'system.listMethods', 'system.getCapabilities',
                'demo.addTwoNumbers', 'demo.sayHello', 'pingback.extensions.getPingbacks',
                'pingback.ping', 'mt.publishPost', 'mt.getTrackbackPings',
                'mt.supportedTextFilters', 'mt.supportedMethods', 'mt.setPostCategories',
                'mt.getPostCategories', 'mt.getRecentPostTitles', 'mt.getCategoryList',
                'metaWeblog.getUsersBlogs', 'metaWeblog.deletePost',
                'metaWeblog.newMediaObject', 'metaWeblog.getCategories',
                'metaWeblog.getRecentPosts', 'metaWeblog.getPost', 'metaWeblog.editPost',
                'metaWeblog.newPost', 'wp.restoreRevision', 'wp.getRevisions',
                'wp.getPostTypes', 'wp.getPostType', 'wp.getPostFormats',
                'wp.getMediaLibrary', 'wp.getMediaItem', 'wp.getCommentStatusList',
                'wp.newComment', 'wp.editComment', 'wp.deleteComment', 'wp.getComments',
                'wp.getComment', 'wp.setOptions', 'wp.getOptions', 'wp.getPageTemplates',
                'wp.getPageStatusList', 'wp.getPostStatusList', 'wp.getCommentCount',
                'wp.deleteFile', 'wp.uploadFile', 'wp.suggestCategories',
                'wp.deleteCategory', 'wp.newCategory', 'wp.getTags', 'wp.getCategories',
                'wp.getAuthors', 'wp.getPageList', 'wp.editPage', 'wp.deletePage',
                'wp.newPage', 'wp.getPages', 'wp.getPage', 'wp.editProfile',
                'wp.getProfile', 'wp.getUsers', 'wp.getUser', 'wp.getTaxonomies',
                'wp.getTaxonomy', 'wp.getTerms', 'wp.getTerm', 'wp.deleteTerm',
                'wp.editTerm', 'wp.newTerm', 'wp.getPostsjson', 'wp.getPosts',
                'wp.deletePost', 'wp.editPost', 'wp.newPost', 'wp.getUsersBlogs'];

    $items = '';
    foreach ($methods as $name) {
        $items .= '<value><string>' . sb_html($name) . '</string></value>';
    }
    header('Content-Type: text/xml; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<methodResponse><params><param><value><array><data>'
        . $items . '</data></array></value></param></params></methodResponse>';
    exit;
}

// Default: the convincing generic response.
header('Content-Type: text/xml; charset=UTF-8');
header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
    . '<methodResponse><params><param><value><string>' . sb_html(COMPANY_SHORT) . '</string>'
    . '</value></param></params></methodResponse>';
exit;

function respond_fault(int $code, string $message): void
{
    header('Content-Type: text/xml; charset=UTF-8');
    header('X-Powered-By: PHP/' . FAKE_PHP_VERSION);
    echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<methodResponse><fault><value><struct>'
        . '<member><name>faultCode</name><value><int>' . $code . '</int></value></member>'
        . '<member><name>faultString</name><value><string>' . sb_html($message)
        . '</string></value></member>'
        . '</struct></value></fault></methodResponse>';
    exit;
}
