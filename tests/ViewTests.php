<?php

declare(strict_types=1);

use Chuck\Routing\Route;
use Chuck\Routing\{View, CallableView, ControllerView};
use Chuck\Tests\Fixtures\TestController;
use Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Closure', function () {
    $route = new Route('/', fn () => 'chuck');
    $route->match('/');
    $view = View::get($this->request(), $route);

    expect($view::class)->toBe(CallableView::class);
    expect($view->execute())->toBe('chuck');
});


test('Function', function () {
    function ____view_test____(string $name): string
    {
        return $name;
    }

    $route = new Route('/{name}', '____view_test____');
    $route->match('/symbolic');
    $view = View::get($this->request(), $route);

    expect($view::class)->toBe(CallableView::class);
    expect($view->execute())->toBe('symbolic');
});


test('Controller String', function () {
    $route = new Route('/', '\Chuck\Tests\Fixtures\TestController::textView');
    $route->match('/');
    $view = View::get($this->request(), $route);

    expect($view::class)->toBe(ControllerView::class);
    expect($view->execute())->toBe('text');
});


test('Controller [class, method]', function () {
    $route = new Route('/', [TestController::class, 'textView']);
    $route->match('/');
    $view = View::get($this->request(), $route);

    expect($view::class)->toBe(ControllerView::class);
    expect($view->execute())->toBe('text');
});


test('Controller [object, method]', function () {
    $controller = new TestController();
    $route = new Route('/', [$controller, 'textView']);
    $route->match('/');
    $view = View::get($this->request(), $route);

    expect($view::class)->toBe(CallableView::class);
    expect($view->execute())->toBe('text');
});
