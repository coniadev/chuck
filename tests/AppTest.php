<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\Config;
use Conia\Chuck\Http\Factory;
use Conia\Chuck\Logger;
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Renderer\TextRenderer;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\Routing\Group;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\Routing\Router;
use Conia\Chuck\Tests\Fixtures\TestRenderer;
use Conia\Chuck\Tests\Setup\C;
use Conia\Chuck\Tests\Setup\TestCase;
use Psr\Log\LoggerInterface;

uses(TestCase::class);


test('Create helper', function () {
    expect(App::create())->toBeInstanceOf(App::class);
});


test('Helper methods', function () {
    $app = App::create();

    expect($app->router())->toBeInstanceOf(Router::class);
    expect($app->config())->toBeInstanceOf(Config::class);
});


test('Config init', function () {
    $app = App::create();

    expect($app->config())->toBeInstanceOf(Config::class);
    expect($app->config()->app())->toBe('chuck');

    $app = App::create(new Config('test'));

    expect($app->config())->toBeInstanceOf(Config::class);
    expect($app->config()->app())->toBe('test');
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

    expect(count($app->router()->getMiddleware()))->toBe(1);
});


test('Static route helper', function () {
    $app = App::create();
    $app->staticRoute('/static', C::root() . C::DS . 'public' . C::DS . 'static', 'static');
    $app->staticRoute('/unnamedstatic', C::root() . C::DS . 'public' . C::DS . 'static');

    expect($app->router()->staticUrl('static', 'test.json'))->toBe('/static/test.json');
    expect($app->router()->staticUrl('/unnamedstatic', 'test.json'))->toBe('/unnamedstatic/test.json');
});


test('App run', function () {
    $app = new App(new Config('chuck'), new Router(), $this->registry());
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
});


test('App run with autowiring turned off', function () {
    $app = new App(new Config('chuck'), new Router(), $this->registry(autowire: false));
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
});


test('App::register helper', function () {
    $app = new App(new Config('chuck'), new Router(), $this->registry());
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

    expect($registry->tag(Renderer::class)->get('test'))->toBe(TestRenderer::class);
});


test('Add logger', function () {
    $app = $this->app();
    $app->Logger(function (): LoggerInterface {
        $logfile = C::root() . C::DS . 'log' . C::DS . bin2hex(random_bytes(4)) . '.log';

        return new Logger(Logger::DEBUG, $logfile);
    });
    $registry = $app->registry();
    $logger = $registry->get(LoggerInterface::class);

    expect($logger)->toBeInstanceOf(Logger::class);

    $logger2 = $registry->get(LoggerInterface::class);

    expect($logger === $logger2)->toBe(true);
});


test('Registry initialized', function () {
    $app = $this->app();
    $registry = $app->registry();

    $value = $registry->get(App::class);
    expect($value)->toBe($app);
    $value = $registry->get(Response::class);
    expect($value instanceof Response)->toBe(true);
    $value = $registry->get(Response::class);
    expect($value instanceof Response)->toBe(true);
    $value = $registry->get(Config::class);
    expect($value instanceof Config)->toBe(true);
    $value = $registry->get(Factory::class);
    expect($value instanceof Factory)->toBe(true);
    expect($registry->tag(Renderer::class)->get('text'))->toBe(TextRenderer::class);
    expect($registry->tag(Renderer::class)->get('json'))->toBe(JsonRenderer::class);
});
