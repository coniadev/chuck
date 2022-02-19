<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Tests\Fix\{TestClass, TestInterface};
use Chuck\{App, Route, Request, Response};
use Chuck\Renderer\Renderer;

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

    $app->middleware(function (Request $request, callable $next): Request|Response {
        return $next($request);
    });

    expect(count($app->router()->middlewares()))->toBe(1);
});


test('Static route helper', function () {
    $ds = DIRECTORY_SEPARATOR;
    $app = App::create($this->options());
    $app->staticRoute('static', '/static', __DIR__ . $ds . 'fixtures' . $ds . 'static');

    expect($app->router()->staticUrl('static', 'test.json'))->toBe('/static/test.json');
});


test('Route helper', function () {
    $app = App::create($this->options());
    $app->route(Route::get('albums', '/albums', 'Chuck\Tests\Fix\Controller::textView'));

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('Register helper', function () {
    $app = App::create($this->options());
    $app->register(TestInterface::class, TestClass::class);

    expect($app->config()->registry(TestInterface::class))->toBe(TestClass::class);
});


test('Renderer helper', function () {
    $app = App::create($this->options());
    class TestRenderer extends Renderer
    {
        function render(): string
        {
            return '';
        }
    }
    $app->renderer('test', TestRenderer::class);

    expect($app->config()->renderer('test'))->toBe(TestRenderer::class);
});


test('App run', function () {
    $app = new App($this->request(method: 'GET', url: '/'));
    $app->route(Route::get('index', '/', 'Chuck\Tests\Fix\Controller::textView'));
    ob_start();
    $response = $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('success');
    expect(in_array('Content-Type: text/html; charset=UTF-8', $response->headersList()))->toBe(true);
    expect(in_array('HTTP/1.1 200', $response->headersList()))->toBe(true);
});
