<?php

declare(strict_types=1);

use Conia\Chuck\Exception\ContainerException;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\Tests\Fixtures\TestAttribute;
use Conia\Chuck\Tests\Fixtures\TestAttributeDiff;
use Conia\Chuck\Tests\Fixtures\TestAttributeExt;
use Conia\Chuck\Tests\Fixtures\TestController;
use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\View;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

require __DIR__ . '/Setup/globalSymbols.php';

uses(TestCase::class);

test('Closure', function () {
    $route = new Route('/', #[TestAttribute] fn () => 'chuck');
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());

    expect($view::class)->toBe(View::class);
    expect($view->execute())->toBe('chuck');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Function', function () {
    $route = new Route('/{name}', '_testViewWithAttribute');
    $route->match('/symbolic');
    $view = new View($route->view(), $route->args(), $this->registry());

    expect($view::class)->toBe(View::class);
    expect($view->execute())->toBe('symbolic');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Controller String', function () {
    $route = new Route('/', '\Conia\Chuck\Tests\Fixtures\TestController::textView');
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());

    expect($view::class)->toBe(View::class);
    expect($view->execute())->toBe('text');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Controller [class, method]', function () {
    $route = new Route('/', [TestController::class, 'textView']);
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());

    expect($view::class)->toBe(View::class);
    expect($view->execute())->toBe('text');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Controller [object, method]', function () {
    $controller = new TestController();
    $route = new Route('/', [$controller, 'textView']);
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());

    expect($view::class)->toBe(View::class);
    expect($view->execute())->toBe('text');
    expect($view->attributes()[0])->toBeInstanceOf(TestAttribute::class);
});


test('Attribute filtering :: Callable view', function () {
    $route = new Route('/', #[TestAttribute, TestAttributeExt, TestAttributeDiff] fn () => 'chuck');
    $view = new View($route->view(), $route->args(), $this->registry());

    expect($view::class)->toBe(View::class);
    expect(count($view->attributes()))->toBe(3);
    expect(count($view->attributes(TestAttribute::class)))->toBe(2);
    expect(count($view->attributes(TestAttributeExt::class)))->toBe(1);
    expect(count($view->attributes(TestAttributeDiff::class)))->toBe(1);
});


test('Attribute filtering :: Controller view', function () {
    $route = new Route('/', [TestController::class, 'arrayView']);
    $view = new View($route->view(), $route->args(), $this->registry());

    expect($view::class)->toBe(View::class);
    expect(count($view->attributes()))->toBe(3);
    expect(count($view->attributes(TestAttribute::class)))->toBe(2);
    expect(count($view->attributes(TestAttributeExt::class)))->toBe(1);
    expect(count($view->attributes(TestAttributeDiff::class)))->toBe(1);
});


test('Untyped closure parameter', function () {
    $route = new Route('/', #[TestAttribute] fn ($param) => 'chuck');
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());
    $view->execute();
})->throws(ContainerException::class, 'Autowired entities');


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


test('View response Response', function () {
    $route = new Route('/', function (Registry $registry) {
        $sf = $registry->get(Psr\Http\Message\StreamFactoryInterface::class);
        $rf = $registry->get(Psr\Http\Message\ResponseFactoryInterface::class);
        $response = new Response($rf->createResponse(), $sf);
        $response->body('Chuck Response');
        $response->header('Content-Type', 'text/plain');

        return $response;
    });
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());
    $response = $view->respond($this->request(), $route, $this->registry(), $this->config());

    expect((string)$response->getBody())->toBe('Chuck Response');
    expect($response->headers()['Content-Type'][0])->toBe('text/plain');
});


test('View response PSR Response', function () {
    $route = new Route('/', function (Registry $registry) {
        $sf = $registry->get(Psr\Http\Message\StreamFactoryInterface::class);
        $rf = $registry->get(Psr\Http\Message\ResponseFactoryInterface::class);

        return $rf->createResponse()
            ->withBody($sf->createStream('Chuck PSR Response'))
            ->withHeader('Content-Type', 'text/plain');
    });
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());
    $response = $view->respond($this->request(), $route, $this->registry(), $this->config());

    expect((string)$response->getBody())->toBe('Chuck PSR Response');
    expect($response->headers()['Content-Type'][0])->toBe('text/plain');
});


test('View response array', function () {
    $route = new Route('/', fn () => ['chuck' => 'schuldiner']);
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());
    $response = $view->respond($this->request(), $route, $this->registry(), $this->config());

    expect((string)$response->getBody())->toBe('{"chuck":"schuldiner"}');
    expect($response->headers()['Content-Type'][0])->toBe('application/json');
});


test('View response string', function () {
    $route = new Route('/', fn () => '<h1>Chuck</h1>');
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());
    $response = $view->respond($this->request(), $route, $this->registry(), $this->config());

    expect((string)$response->getBody())->toBe('<h1>Chuck</h1>');
    expect($response->headers()['Content-Type'][0])->toBe('text/html');
});


test('View response Stringable', function () {
    $route = new Route('/', fn () => new class () {
        public function __toString(): string
        {
            return '<h1>Chuck</h1>';
        }
    });
    $route->match('/');
    $view = new View($route->view(), $route->args(), $this->registry());
    $response = $view->respond($this->request(), $route, $this->registry(), $this->config());

    expect((string)$response->getBody())->toBe('<h1>Chuck</h1>');
    expect($response->headers()['Content-Type'][0])->toBe('text/html');
});
