<?php

declare(strict_types=1);

use Chuck\Config;
use Chuck\Request;


test('Config defaults', function () {
    $config = new Config([]);

    expect($config->get('devport'))->toBe(1983);
});


test('Config custom options', function () {
    $config = new Config([
        'album' => 'Symbolic',
        'path' => [
            'root' => __DIR__,
        ],
    ]);

    expect($config->get('devport'))->toBe(1983);
    expect($config->get('album'))->toBe('Symbolic');
    expect($config->path('root'))->toBe(__DIR__);
});


test('Config default value', function () {
    $config = new Config([]);

    expect($config->get('devport', 1984))->toBe(1983);
    expect($config->get('url', 'http://example.com'))->toBe('http://example.com');
    expect($config->get('url', 'http://example.com'))->toBe('http://example.com');

    // missing/invalid key with default
    expect($config->get('missing', 'default'))->toBe('default');
});


test('Config missing key', function () {
    $config = new Config([]);

    $config->get('missing');
})->throws(\InvalidArgumentException::class);


test('Config path is array', function () {
    $config = new Config([
        'path' => [
            'array' => [
                '/first',
                '/second',
            ],
        ],
    ]);

    expect($config->path('array'))->toBe(['/first', '/second']);
});
