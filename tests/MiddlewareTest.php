<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\Renderer\Render;
use Conia\Chuck\Route;
use Conia\Chuck\Tests\Fixtures\TestMiddlewareAutowire;
use Conia\Chuck\Tests\Fixtures\TestMiddlewareEarlyResponse;
use Conia\Chuck\Tests\Fixtures\TestMiddlewareObject;
use Conia\Chuck\Tests\Fixtures\TestPsrMiddlewareObject;
use Conia\Chuck\Tests\Setup\TestCase;

require __DIR__ . '/Setup/globalSymbols.php';

uses(TestCase::class);

test('Middleware flow', function () {
    $app = App::create();
    $route = new Route('/', 'Conia\Chuck\Tests\Fixtures\TestController::middlewareView');
    $route->middleware([TestMiddlewareObject::class, ' last']);
    $app->addRoute($route);
    $app->middleware('_testFunctionMiddleware');

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('first view last');
});

test('Middleware flow with attribute', function () {
    $app = App::create();
    $route = new Route('/', 'Conia\Chuck\Tests\Fixtures\TestController::attributedMiddlewareView');
    $route->middleware([TestMiddlewareObject::class, ' last']);
    $app->addRoute($route);
    $app->middleware('_testFunctionMiddleware');

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('first attribute-string last');
});

test('Early response', function () {
    $app = App::create();
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::middlewareView');
    $app->middleware([TestMiddlewareEarlyResponse::class, 'immediate response']);
    $app->middleware(new TestMiddlewareObject(' second'));

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('immediate response');
});

test('Middleware flow with attribute and PSR-15 middleware', function () {
    $app = App::create();
    $route = new Route('/', 'Conia\Chuck\Tests\Fixtures\TestController::attributedMiddlewareView');
    $route->middleware(new TestMiddlewareObject(' last'));
    $route->middleware([TestPsrMiddlewareObject::class, ' PSR']);
    $app->addRoute($route);
    $app->middleware('_testFunctionMiddleware');

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('first attribute-string PSR last');
});

test('Middleware autowiring', function () {
    $app = App::create();
    $route = new Route('/', #[Render('text')] fn () => '');
    $route->middleware(TestMiddlewareAutowire::class);
    $app->addRoute($route);

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('chuck Conia\Chuck\Registry');
});
