<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\{TestCase, C};
use Conia\Chuck\Routing\{Router, Route, Group};
use Conia\Chuck\Response;
use Conia\Chuck\{App, Request, Config};
use Conia\Chuck\Exception\ContainerException;

uses(TestCase::class);


test('Create helper', function () {
    expect(App::create($this->config()))->toBeInstanceOf(App::class);
});


test('Helper methods', function () {
    $app = App::create($this->config());

    expect($app->router())->toBeInstanceOf(Router::class);
    expect($app->config())->toBeInstanceOf(Config::class);
});


test('Create with third party container', function () {
    $container = new League\Container\Container();
    $container->add('external', new stdClass());
    $app = App::create($this->config(), $container);

    expect($app->registry()->get('external') instanceof stdClass)->toBe(true);
});


test('Fail on register helper when using third party container', function () {
    $container = new League\Container\Container();
    $app = App::create($this->config(), $container);

    $app->register('external', new stdClass());
})->throws(ContainerException::class, 'Third party container');


test('Middleware helper', function () {
    $app = App::create($this->config());

    $app->middleware(function (Request $request, callable $next): Request|Response {
        return $next($request);
    });

    expect(count($app->router()->getMiddleware()))->toBe(1);
});


test('Static route helper', function () {
    $app = App::create($this->config());
    $app->staticRoute('/static', C::root() . C::DS . 'public' . C::DS . 'static', 'static');
    $app->staticRoute('/unnamedstatic', C::root() . C::DS . 'public' . C::DS . 'static');

    expect($app->router()->staticUrl('static', 'test.json'))->toBe('/static/test.json');
    expect($app->router()->staticUrl('/unnamedstatic', 'test.json'))->toBe('/unnamedstatic/test.json');
});


test('App run', function () {
    $request = $this->request(method: 'GET', url: '/');
    $app = new App($this->config(), new Router(), $this->registry());
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
});


test('App::register helper', function () {
    $app = new App($this->config(), new Router(), $this->registry());
    $app->register('Chuck', 'Schuldiner')->asIs();
    $registry = $app->registry();

    expect($registry->get('Chuck'))->toBe('Schuldiner');
});


test('App::addRoute/::addGroup helper', function () {
    $app = App::create($this->config());
    $route = new Route('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');
    $group = new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;
        $group->addRoute(Route::get('/{name}', "$ctrl::albumName", 'name'));
    }, 'albums:');
    $app->addRoute($route);
    $app->addGroup($group);

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
    expect($app->router()->routeUrl('albums:name', ['name' => 'symbolic']))->toBe('/albums/symbolic');
});


test('App::route helper', function () {
    $app = App::create($this->config());
    $app->route('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::get helper', function () {
    $app = App::create($this->config());
    $app->get('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::post helper', function () {
    $app = App::create($this->config());
    $app->post('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::put helper', function () {
    $app = App::create($this->config());
    $app->put('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::patch helper', function () {
    $app = App::create($this->config());
    $app->patch('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::delete helper', function () {
    $app = App::create($this->config());
    $app->delete('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::head helper', function () {
    $app = App::create($this->config());
    $app->head('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::options helper', function () {
    $app = App::create($this->config());
    $app->options('/albums', 'Chuck\Tests\Fixtures\TestController::textView', 'albums');

    expect($app->router()->routeUrl('albums'))->toBe('/albums');
});


test('App::group helper', function () {
    $app = App::create($this->config());
    $app->group('/albums', function (Group $group) {
        $ctrl = TestController::class;
        $group->addRoute(Route::get('/{name}', "$ctrl::albumName", 'name'));
    }, 'albums:');

    expect($app->router()->routeUrl('albums:name', ['name' => 'symbolic']))->toBe('/albums/symbolic');
});
