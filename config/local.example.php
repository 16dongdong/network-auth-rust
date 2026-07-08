<?php
defined('IN_CRONLITE') || exit();

define('SYS_KEY', 'replace-with-a-random-64-byte-secret');
define('AUTH_ADMIN_TOKEN_HASH', 'replace-with-admin-token-sha256-or-hmac-hash');
define('NETWORK_AUTH_DEMO_MODE', false);

$dbconfig = [
    'host' => '127.0.0.1',
    'port' => 3306,
    'user' => 'network_auth',
    'pwd' => 'change-me',
    'dbname' => 'network_auth',
];
