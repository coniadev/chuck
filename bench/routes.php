<?php

/**
 * Testcase 1000 routes, 250x4 matches
 *
 * Before commit 5bec166:
 *   Setup routes
 *   0.0038859844207764
 *   Match routes
 *   4.2557730674744
 *
 * After commit 5bec166:
 *   Setup routes
 *   0.0043048858642578
 *   Match routes
 *   1.9602971076965
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Chuck\Request;
use Chuck\Routing\{Router, Route};
use Chuck\Config;
use Chuck\Error\{HttpNotFound, HttpMethodNotAllowed};


$config = new Config([
    'app' => 'chuck',
    'path.root' => __DIR__,
    'path.root' => __DIR__,
]);

function request(
    string $method,
    string $url,
    Config $config,
    Router $router,
): Request {
    $_SERVER['REQUEST_METHOD'] = $method;
    $_SERVER['REQUEST_URI'] = $url;

    return new Request($config, $router);
}

print("Setup routes\n");
$start = microtime(true);
$router = new Router();
for ($i = 0; $i < 1000; $i++) {
    $method = [null, 'GET', 'POST', 'DELETE', 'PUT'][$i % 5];

    if ($method === null) {
        $route = new Route('index' . $i, '/test/' . $i, fn () => null);
    } else {
        $route = (new Route('index' . $i, '/test/' . $i, fn () => null))->method($method);
    }

    $router->addRoute($route);
}
$end = microtime(true);
print (string)($end - $start) . "\n";


print("Match routes\n");
$start = microtime(true);
for ($i = 0; $i < 250; $i++) {
    $router->match(request('OPTIONS', '/test/995', $config, $router));
    $router->match(request('POST', '/test/997', $config, $router));

    try {
        $router->match(request('GET', '/test/999', $config, $router));
    } catch (HttpMethodNotAllowed) {
        continue;
    }

    try {
        $router->match(request('GET', '/test/1001', $config, $router));
    } catch (HttpNotFound) {
        continue;
    }
}
$end = microtime(true);
print (string)($end - $start) . "\n";
