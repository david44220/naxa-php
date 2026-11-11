<?php

declare(strict_types=1);

/*
 * A tiny HTTP server for the test of the curl transport (`php -S 127.0.0.1:<port> tests/server.php`):
 * it says back what it received, redirects, answers too much or too late, as asked by the path.
 */

$path = (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/redirect') {
    header('Location: /echo', true, 302);
    exit;
}
if ($path === '/big') {
    header('Content-Type: application/json');
    echo str_repeat('a', 3_000_000);
    exit;
}
if ($path === '/slow') {
    sleep(3);
    echo '{}';
    exit;
}
header('Content-Type: application/json');
header('X-Request-Id: req_local');
http_response_code($path === '/created' ? 201 : 200);
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'headers' => array_change_key_case(getallheaders(), CASE_LOWER),
    'body' => file_get_contents('php://input'),
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
