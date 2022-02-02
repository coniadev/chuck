<?php

declare(strict_types=1);

use Chuck\Config;
use Chuck\Request;
use Chuck\Response;
use Chuck\Renderer\JsonRenderer;
use Chuck\Renderer\TemplateRenderer;


test('Config defaults', function () {
    $config = new Config([]);

    expect($config->get('devport'))->toBe(1983);
    expect($config->di('Request'))->toBe(Request::class);
    expect($config->get('renderer')['json'])->toBe(JsonRenderer::class);
});


test('Config custom options', function () {
    $config = new Config([
        'album' => 'Symbolic',
        'path' => [
            'root' => __DIR__,
        ],
        'di' => [
            'Additional' => Additional::class,
            'Request' => FantasyRequest::class,
        ],
        'renderer' => [
            'json' => FantasyJsonRenderer::class,
        ],
    ]);
    echo (Request::class . PHP_EOL);

    expect($config->get('devport'))->toBe(1983);
    expect($config->get('album'))->toBe('Symbolic');
    expect($config->get('renderer')['template'])->toBe(TemplateRenderer::class);
    expect($config->get('renderer')['json'])->toBe(FantasyJsonRenderer::class);
    expect($config->path('root'))->toBe(__DIR__);
    expect($config->di('Request'))->toBe(FantasyRequest::class);
    expect($config->di('Response'))->toBe(Response::class);
    expect($config->di('Additional'))->toBe(Additional::class);
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
