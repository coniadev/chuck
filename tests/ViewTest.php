<?php

declare(strict_types=1);

use Conia\Chuck\Exception\UnresolvableException;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\View\{View, CallableView, ControllerView};
use Conia\Chuck\Tests\Fixtures\{TestController, TestAttribute, TestAttributeExt, TestAttributeDiff};
use Conia\Chuck\Tests\Setup\TestCase;

require __DIR__ . '/Setup/globalSymbols.php';

uses(TestCase::class);


test('Closure', function () {
    $route = new Route('/', #[TestAttribute] fn () => 'chuck');
    $route->match('/');
    $view = View::get($route, $this->registry());

    expect($view::class)->toBe(CallableView::class);
    expect($view->execute())->toBe('chuck');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Function', function () {
    $route = new Route('/{name}', '_testViewWithAttribute');
    $route->match('/symbolic');
    $view = View::get($route, $this->registry());

    expect($view::class)->toBe(CallableView::class);
    expect($view->execute())->toBe('symbolic');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Controller String', function () {
    $route = new Route('/', '\Conia\Chuck\Tests\Fixtures\TestController::textView');
    $route->match('/');
    $view = View::get($route, $this->registry());

    expect($view::class)->toBe(ControllerView::class);
    expect($view->execute())->toBe('text');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Controller [class, method]', function () {
    $route = new Route('/', [TestController::class, 'textView']);
    $route->match('/');
    $view = View::get($route, $this->registry());

    expect($view::class)->toBe(ControllerView::class);
    expect($view->execute())->toBe('text');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Controller [object, method]', function () {
    $controller = new TestController();
    $route = new Route('/', [$controller, 'textView']);
    $route->match('/');
    $view = View::get($route, $this->registry());

    expect($view::class)->toBe(CallableView::class);
    expect($view->execute())->toBe('text');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Attribute filtering :: CallableView', function () {
    $route = new Route('/', #[TestAttribute, TestAttributeExt, TestAttributeDiff] fn () => 'chuck');
    $view = View::get($route, $this->registry());

    expect($view::class)->toBe(CallableView::class);
    expect(count($view->attributes()))->toBe(3);
    expect(count($view->attributes(TestAttribute::class)))->toBe(2);
    expect(count($view->attributes(TestAttributeExt::class)))->toBe(1);
    expect(count($view->attributes(TestAttributeDiff::class)))->toBe(1);
});


test('Attribute filtering :: ControllerView', function () {
    $route = new Route('/', [TestController::class, 'arrayView']);
    $view = View::get($route, $this->registry());

    expect($view::class)->toBe(ControllerView::class);
    expect(count($view->attributes()))->toBe(3);
    expect(count($view->attributes(TestAttribute::class)))->toBe(2);
    expect(count($view->attributes(TestAttributeExt::class)))->toBe(1);
    expect(count($view->attributes(TestAttributeDiff::class)))->toBe(1);
});


test('Untyped closure parameter', function () {
    $route = new Route('/', #[TestAttribute] fn ($param) => 'chuck');
    $route->match('/');
    $view = View::get($route, $this->registry());
    $view->execute();
})->throws(UnresolvableException::class, 'Autowired entities');

test('Reflect function', function () {
    $rf = View::getReflectionFunction(function () {
    });
    expect($rf)->toBeInstanceOf(ReflectionFunction::class);

    $rf = View::getReflectionFunction(new class () {
        public function __invoke(): string
        {
            return '';
        }
    });
    expect($rf)->toBeInstanceOf(ReflectionMethod::class);

    $rf = View::getReflectionFunction('is_string');
    expect($rf)->toBeInstanceOf(ReflectionFunction::class);
});
