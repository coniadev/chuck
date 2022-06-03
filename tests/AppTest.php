<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Tests\Fixtures\{TestClass, TestInterface, TestRenderer};
use Chuck\Routing\{Router, Route};
use Chuck\{App, Request, Response, Config};

uses(TestCase::class);


test('Create helper', function () {
    expect(App::create($this->config()))->toBeInstanceOf(App::class);
});


test('Helper methods', function () {
    $app = App::create($this->config());

    expect($app->request())->toBeInstanceOf(Request::class);
    expect($app->router())->toBeInstanceOf(Router::class);
    expect($app->config())->toBeInstanceOf(Config::class);
});


test('Middleware helper', function () {
    $app = App::create($this->config());

    $app->middleware(function (Request $request, callable $next): Request|Response {
        return $next($request);
    });

    expect(count($app->router()->middlewares()))->toBe(1);
});


test('Static route helper', function () {
    $app = App::create($this->config());
    $app->static('static', '/static', C::root() . C::DS . 'public' . C::DS . 'static');

    expect($app->router()->staticUrl('static', 'test.json'))->toBe('/static/test.json');
});


test('Route helper', function () {
    $app = App::create($this->config());
    $app->add(Route::get('albums', '/albums', 'Chuck\Tests\Fixtures\TestController::textView'));

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App run', function () {
    $request = $this->request(method: 'GET', url: '/');
    $app = new App($request, $request->getConfig(), $request->getRouter());
    $app->add(Route::get('index', '/', 'Chuck\Tests\Fixtures\TestController::textView'));
    ob_start();
    $response = $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('success');
    expect(in_array('Content-Type: text/html; charset=UTF-8', $response->getHeaderList()))->toBe(true);
    expect(in_array('HTTP/1.1 200 OK', $response->getHeaderList()))->toBe(true);
});
