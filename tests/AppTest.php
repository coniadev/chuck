<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\Error\ErrorRenderer;
use Conia\Chuck\Error\Handler;
use Conia\Chuck\Factory;
use Conia\Chuck\Group;
use Conia\Chuck\Logger;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\Route;
use Conia\Chuck\Router;
use Conia\Chuck\Tests\Fixtures\TestRenderer;
use Conia\Chuck\Tests\Setup\C;
use Conia\Chuck\Tests\Setup\TestCase;
use Psr\Log\LoggerInterface as PsrLogger;

uses(TestCase::class);

test('Create helper', function () {
    expect(App::create())->toBeInstanceOf(App::class);
});

test('Helper methods', function () {
    $app = App::create();

    expect($app->router())->toBeInstanceOf(Router::class);
});

test('Create with third party container', function () {
    $container = new League\Container\Container();
    $container->add('external', new stdClass());
    $app = App::create(null, $container);

    expect($app->registry()->get('external') instanceof stdClass)->toBe(true);
});

test('Middleware helper', function () {
    $app = App::create();

    $app->middleware(function (Request $request, callable $next): Response {
        return $next($request);
    });

    // The error handler middleware is always added when using ::create()
    expect(count($app->router()->getMiddleware()))->toBe(2);
});

test('Static route helper', function () {
    $app = App::create();
    $app->staticRoute('/static', C::root() . '/public/static', 'static');
    $app->staticRoute('/unnamedstatic', C::root() . '/public/static');

    expect($app->router()->staticUrl('static', 'test.json'))->toBe('/static/test.json');
    expect($app->router()->staticUrl('/unnamedstatic', 'test.json'))->toBe('/unnamedstatic/test.json');
});

test('App run', function () {
    $app = new App(new Router(), $this->registry());
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
});

test('App run with autowiring turned off', function () {
    $app = new App(new Router(), $this->registry(autowire: false));
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
});

test('App::register helper', function () {
    $app = new App(new Router(), $this->registry());
    $app->register('Chuck', 'Schuldiner')->asIs();
    $registry = $app->registry();

    expect($registry->get('Chuck'))->toBe('Schuldiner');
});

test('App::addRoute/::addGroup helper', function () {
    $app = App::create();
    $route = new Route('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');
    $group = new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;
        $group->addRoute(Route::get('/{name}', "{$ctrl}::albumName", 'name'));
    }, 'albums:');
    $app->addRoute($route);
    $app->addGroup($group);

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
    expect($app->router()->routeUrl('albums:name', ['name' => 'symbolic']))->toBe('/albums/symbolic');
});

test('App::route helper', function () {
    $app = App::create();
    $app->route('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::routes helper', function () {
    $app = App::create();
    $app->routes(function (Router $r): void {
        $r->get('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');
    });

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::get helper', function () {
    $app = App::create();
    $app->get('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::post helper', function () {
    $app = App::create();
    $app->post('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::put helper', function () {
    $app = App::create();
    $app->put('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::patch helper', function () {
    $app = App::create();
    $app->patch('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::delete helper', function () {
    $app = App::create();
    $app->delete('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::head helper', function () {
    $app = App::create();
    $app->head('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::options helper', function () {
    $app = App::create();
    $app->options('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});

test('App::group helper', function () {
    $app = App::create();
    $app->group('/albums', function (Group $group) {
        $ctrl = TestController::class;
        $group->addRoute(Route::get('/{name}', "{$ctrl}::albumName", 'name'));
    }, 'albums:');

    expect($app->router()->routeUrl('albums:name', ['name' => 'symbolic']))->toBe('/albums/symbolic');
});

test('Add renderer', function () {
    $app = App::create();
    $app->renderer('test', TestRenderer::class);
    $registry = $app->registry();

    expect($registry->tag(Renderer::class)->get('test'))->toBeInstanceOf(TestRenderer::class);
});

test('Add error renderer', function () {
    $app = App::create();
    $app->errorRenderer('test', 'testError', arg: 1);
    $registry = $app->registry();
    $config = $registry->tag(Handler::class)->get('test');

    expect($config)->toBeInstanceOf(ErrorRenderer::class);
    expect($config->renderer)->toBe('testError');
    expect($config->args['arg'])->toBe(1);
});

test('Add logger', function () {
    $app = $this->app();
    $app->Logger(function (): PsrLogger {
        $logfile = C::root() . '/log/' . bin2hex(random_bytes(4)) . '.log';

        return new Logger(Logger::DEBUG, $logfile);
    });
    $registry = $app->registry();
    $logger = $registry->get(PsrLogger::class);

    expect($logger)->toBeInstanceOf(Logger::class);

    $logger2 = $registry->get(PsrLogger::class);

    expect($logger === $logger2)->toBe(true);
});

test('Registry initialized', function () {
    $app = $this->app();
    $registry = $app->registry();

    $value = $registry->get(Response::class);
    expect($value instanceof Response)->toBe(true);
    $value = $registry->get(Response::class);
    expect($value instanceof Response)->toBe(true);
    $value = $registry->get(Factory::class);
    expect($value instanceof Factory)->toBe(true);
    expect($registry->tag(Renderer::class)->get('text'))
        ->toBeInstanceOf(\Conia\Chuck\Renderer\TextRenderer::class);
    expect($registry->tag(Renderer::class)->get('json'))
        ->toBeInstanceOf(\Conia\Chuck\Renderer\JsonRenderer::class);
    expect($registry->tag(Renderer::class)->get('html'))
        ->toBeInstanceOf(\Conia\Chuck\Renderer\HtmlRenderer::class);
    expect($registry->tag(Renderer::class)->get('textError'))
        ->toBeInstanceOf(\Conia\Chuck\Renderer\TextErrorRenderer::class);
    expect($registry->tag(Renderer::class)->get('jsonError'))
        ->toBeInstanceOf(\Conia\Chuck\Renderer\JsonErrorRenderer::class);
    expect($registry->tag(Renderer::class)->get('htmlError'))
        ->toBeInstanceOf(\Conia\Chuck\Renderer\HtmlErrorRenderer::class);

    expect($registry->tag(Handler::class)->get('text/plain')->renderer)->toBe('textError');
    expect($registry->tag(Handler::class)->get('text/html')->renderer)->toBe('htmlError');
    expect($registry->tag(Handler::class)->get('application/json')->renderer)->toBe('jsonError');
});
