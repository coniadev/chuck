<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\{Router, Route};

uses(TestCase::class);

test('Matching', function () {
    $router = new Router();

    $index = new Route('index', '/', fn () => null);
    $router->addRoute($index);
    $albums = new Route('albums', '/albums', fn () => null);
    $router->addRoute($albums);

    expect($router->match($this->request(method: 'GET', url: '')))->toBe($index);
    expect($router->match($this->request(method: 'GET', url: '/albums')))->toBe($albums);
});


test('Generate route url', function () {
    $router = new Router();
    $albums = new Route('albums', '/albums/{from}/{to}', fn () => null);
    $router->addRoute($albums);


    expect($router->routeUrl('albums', from: 1990, to: 1995))->toBe('http://www.example.com/albums/1990/1995');
    $this->enableHttps();
    expect($router->routeUrl('albums', ['from' => 1988, 'to' => 1991]))->toBe('https://www.example.com/albums/1988/1991');
    $this->disableHttps();
});


test('Static routes', function () {
    $ds = DIRECTORY_SEPARATOR;

    $router = new Router();
    $router->addStatic('static', '/static', __DIR__ . $ds . 'fixtures' . $ds . 'static');
    expect($router->staticUrl('static', 'test.json'))->toBe('http://www.example.com/static/test.json');
    expect($router->staticUrl('static', 'test.json', true))->toMatch('/\?v=[a-f0-9]{6}$/');
    expect($router->staticUrl('static', 'test.json?exists=true', true))->toMatch('/\?exists=true&v=[a-f0-9]{6}$/');
    expect($router->staticUrl(
        'static',
        'test.json',
        host: 'https://chuck.local/',
        bust: true,
    ))->toMatch('/https:\/\/chuck.local\/static\/test.json\?v=[a-f0-9]{6}$/');
});


test('Dispatch without renderer', function () {
    $router = new Router();
    $index = new Route('index', '/', fn (Request $request) => {
        return new Response(
    });
    $router->addRoute($index);

    expect($router->match($this->request(method: 'GET', url: '/albums')))->toBe($albums);
});
