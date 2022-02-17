<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\{App, Route, Request};

uses(TestCase::class);


test('Create helper', function () {
    expect(App::create($this->options()))->toBeInstanceOf(App::class);
});


test('Helper methods', function () {
    $app = App::create($this->options());

    expect($app->request())->toBeInstanceOf(\Chuck\Request::class);
    expect($app->router())->toBeInstanceOf(\Chuck\Router::class);
    expect($app->config())->toBeInstanceOf(\Chuck\Config::class);
});


test('Middleware helper', function () {
    $app = App::create($this->options());

    $app->middleware(function (Request $request, callable $next): Request {
        return $next($request);
    });

    expect(count($app->router()->middlewares()))->toBe(1);
});


test('App run', function () {
    $app = new App($this->request(method: 'GET', url: '/'));
    $app->route(Route::get('index', '/', 'Chuck\Tests\Controller::textView'));
    ob_start();
    $response = $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('success');
    expect(in_array('Content-Type: text/html; charset=UTF-8', $response->headersList()))->toBe(true);
    expect(in_array('HTTP/1.1 200', $response->headersList()))->toBe(true);
});
