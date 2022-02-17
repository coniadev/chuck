<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\{Router, Route, Request, Response};

uses(TestCase::class);


class Middleware
{
    public function __invoke(Request $request, callable $next): Request
    {
        return $next($request);
    }
}


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
    $index = new Route('index', '/', fn (Request $request) => new Response($request, 200, 'Chuck'));
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/'));
    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getBody())->toBe('Chuck');
});


test('Middleware add', function () {
    $router = new Router();

    $router->middleware(function (Request $request, callable $next): Request {
        return $next($request);
    });
    $router->middleware(new Middleware());

    expect(count($router->middlewares()))->toBe(2);
});


test('Middleware :: wrong return type', function () {
    $router = new Router();

    $router->middleware(function (Request $request, callable $next): int {
        return $next($request);
    });
})->throws(\InvalidArgumentException::class);


test('Middleware :: no return type', function () {
    $router = new Router();

    $router->middleware(function (Request $request, callable $next) {
        return $next($request);
    });
})->throws(\InvalidArgumentException::class);


test('Middleware :: wrong parameter count', function () {
    $router = new Router();

    $router->middleware(function (Request $request) {
        return $request;
    });
})->throws(\InvalidArgumentException::class);


test('Middleware :: wrong parameter type I', function () {
    $router = new Router();

    $router->middleware(function (string $request, callable $next) {
        return $next($request);
    });
})->throws(\InvalidArgumentException::class);


test('Middleware :: wrong parameter type II', function () {
    $router = new Router();

    $router->middleware(function (Request $request, int $next) {
        return $next . $request;
    });
})->throws(\InvalidArgumentException::class);
