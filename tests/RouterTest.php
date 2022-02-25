<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Tests\Fixtures\TestMiddleware1;
use Chuck\Tests\Fixtures\TestController;
use Chuck\Tests\Fixtures\TestControllerWithRequest;
use Chuck\{Request, Response};
use Chuck\Routing\{Router, Route};

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
    $albums = new Route('albums', 'albums/{from}/{to}', fn () => null);
    $router->addRoute($albums);

    expect($router->routeUrl('albums', from: 1990, to: 1995))->toBe('/albums/1990/1995');
    $this->enableHttps();
    expect($router->routeUrl('albums', ['from' => 1988, 'to' => 1991]))->toBe('/albums/1988/1991');
    $this->disableHttps();
});


test('Static routes', function () {
    $ds = DIRECTORY_SEPARATOR;
    $router = new Router();
    $router->addStatic('static', '/static', __DIR__ . $ds . 'Fixtures' . $ds . 'static');

    expect($router->staticUrl('static', 'test.json'))->toBe('/static/test.json');
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
    expect((string)$response->getBody())->toBe('Chuck');
});


test('Dispatch wrong view return type', function () {
    $router = new Router();
    $index = new Route('index', '/', TestControllerWithRequest::class . '::wrongReturnType');
    $router->addRoute($index);
    $router->dispatch($this->request(method: 'GET', url: '/'));
})->throws(\ValueError::class, 'Cannot determine a handler');


test('Dispatch controller with request constructor', function () {
    $router = new Router();
    $index = new Route('index', '/', TestControllerWithRequest::class . '::requestOnly');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/'));
    expect((string)$response->getBody())->toBe('Chuck\Request');
});


test('Dispatch view with route params', function () {
    $router = new Router();
    $index = (new Route(
        'params',
        '/{string}/{float}-{int}',
        TestControllerWithRequest::class . '::routeParams'
    ))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic/7.13-23'));
    expect((string)$response->getBody())->toBe(
        '{"string":"symbolic","float":7.13,"int":23,"request":"Chuck\\\\Request"}'
    );
});


test('Dispatch view with route params including request', function () {
    $router = new Router();
    $index = (new Route(
        'params',
        '/{int}/{string}-{float}',
        TestController::class . '::routeParams'
    ))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/17/spiritual-healing-23.31'));
    expect((string)$response->getBody())->toBe(
        '{"string":"spiritual-healing","float":23.31,"int":17,"request":"Chuck\\\\Request"}'
    );
});


test('Middleware add', function () {
    $router = new Router();

    $router->middleware(function (Request $request, callable $next): Response|Request {
        return $next($request);
    });
    $router->middleware(new TestMiddleware1());

    expect(count($router->middlewares()))->toBe(2);
});
