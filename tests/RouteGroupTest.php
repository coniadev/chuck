<?php

declare(strict_types=1);

use Conia\Chuck\Error\HttpMethodNotAllowed;
use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\Tests\Fixtures\{
    TestController,
    TestMiddleware1,
    TestMiddleware2,
    TestMiddleware3
};
use Conia\Chuck\Routing\{Router, Route, Group};

uses(TestCase::class);


test('Matching :: named', function () {
    $router = new Router();
    $index = new Route('/', fn () => null, 'index');
    $router->addRoute($index);

    $group = new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->addRoute(Route::get('/home', "$ctrl::albumHome", 'home'));
        $group->addRoute(Route::get('/{name}', "$ctrl::albumName", 'name'));
        $group->addRoute(Route::get('', "$ctrl::albumList", 'list'));
    }, 'albums:');
    $group->create($router);

    expect($router->match($this->request(method: 'GET', url: ''))->name())->toBe('index');
    expect($router->match($this->request(method: 'GET', url: '/albums/symbolic'))->name())->toBe('albums:name');
    expect($router->match($this->request(method: 'GET', url: '/albums/home'))->name())->toBe('albums:home');
    expect($router->match($this->request(method: 'GET', url: '/albums'))->name())->toBe('albums:list');
    expect($router->routeUrl('albums:name', name: 'symbolic'))->toBe('/albums/symbolic');
});


test('Matching :: unnamed', function () {
    $router = new Router();
    $index = new Route('/', fn () => null);
    $router->addRoute($index);

    $group = new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->addRoute(Route::get('/home', "$ctrl::albumHome"));
        $group->addRoute(Route::get('/{name}', "$ctrl::albumName"));
        $group->addRoute(Route::get('', "$ctrl::albumList"));
    });
    $group->create($router);

    expect($router->match($this->request(method: 'GET', url: ''))->name())->toBe('/');
    expect($router->match($this->request(method: 'GET', url: '/albums/symbolic'))->name())->toBe('/albums/{name}');
    expect($router->match($this->request(method: 'GET', url: '/albums/home'))->name())->toBe('/albums/home');
    expect($router->match($this->request(method: 'GET', url: '/albums'))->name())->toBe('/albums');
    expect($router->routeUrl('/albums/{name}', name: 'symbolic'))->toBe('/albums/symbolic');
});


test('Matching :: with helper methods', function () {
    $router = new Router();
    $index = new Route('/', fn () => null);
    $router->addRoute($index);

    $group = new Group('/helper', function (Group $group) {
        $ctrl = TestController::class;

        $group->get('/get', "$ctrl::albumHome", 'getroute');
        $group->post('/post', "$ctrl::albumHome", 'postroute');
        $group->put('/put', "$ctrl::albumHome", 'putroute');
        $group->patch('/patch', "$ctrl::albumHome", 'patchroute');
        $group->delete('/delete', "$ctrl::albumHome", 'deleteroute');
        $group->options('/options', "$ctrl::albumHome", 'optionsroute');
        $group->head('/head', "$ctrl::albumHome", 'headroute');
        $group->route('/route', "$ctrl::albumHome", 'allroute');
    }, 'helper:');
    $group->create($router);

    expect($router->match($this->request(method: 'GET', url: '/helper/get'))->name())->toBe('helper:getroute');
    expect($router->match($this->request(method: 'POST', url: '/helper/post'))->name())->toBe('helper:postroute');
    expect($router->match($this->request(method: 'PUT', url: '/helper/put'))->name())->toBe('helper:putroute');
    expect($router->match($this->request(method: 'PATCH', url: '/helper/patch'))->name())->toBe('helper:patchroute');
    expect($router->match($this->request(method: 'DELETE', url: '/helper/delete'))->name())->toBe('helper:deleteroute');
    expect($router->match($this->request(method: 'OPTIONS', url: '/helper/options'))->name())->toBe('helper:optionsroute');
    expect($router->match($this->request(method: 'HEAD', url: '/helper/head'))->name())->toBe('helper:headroute');
    expect($router->match($this->request(method: 'GET', url: '/helper/route'))->name())->toBe('helper:allroute');
    expect($router->match($this->request(method: 'HEAD', url: '/helper/route'))->name())->toBe('helper:allroute');
    // raises not allowed
    $router->match($this->request(method: 'GET', url: '/helper/delete'));
})->throws(HttpMethodNotAllowed::class);


test('Renderer', function () {
    $router = new Router();

    $group = (new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->addRoute(Route::get('', "$ctrl::albumList"));

        // overwrite group renderer
        $group->addRoute(Route::get('/home', "$ctrl::albumHome")->render('template:home.php'));

        $group->addRoute(Route::get('/{name}', "$ctrl::albumName"));
    }))->render('json');
    $group->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/albums/human'));
    expect($route->getRenderer()->type)->toBe('json');

    $route = $router->match($this->request(method: 'GET', url: '/albums/home'));
    expect($route->getRenderer()->type)->toBe('template:home.php');

    $route = $router->match($this->request(method: 'GET', url: '/albums'));
    expect($route->getRenderer()->type)->toBe('json');
});

test('Controller prefixing', function () {
    $router = new Router();
    $index = new Route('/', fn () => null);
    $router->addRoute($index);

    $group = (new Group('/albums', function (Group $group) {
        $group->addRoute(Route::get('-list', '::albumList', 'list'));
    }, 'albums-'))->controller(TestController::class);
    $group->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/albums-list'));
    expect($route->name())->toBe('albums-list');
    expect($route->view())->toBe(TestController::class . '::albumList');
});


test('Controller prefixing error', function () {
    $router = new Router();

    $group = (new Group('/albums', function (Group $group) {
        $group->addRoute(Route::get('-list', function () {
        }));
    }))->controller(TestController::class);
    $group->create($router);
})->throws(ValueError::class, 'Cannot add controller');


test('Middleware', function () {
    $router = new Router();
    $router->addMiddleware(new TestMiddleware1());

    $group = (new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->addRoute(Route::get('', "$ctrl::albumList"));
        $group->addRoute(Route::get('/home', "$ctrl::albumHome")->middleware(new TestMiddleware3()));
        $group->addRoute(Route::get('/{name}', "$ctrl::albumName"));
    }))->middleware(new TestMiddleware2());
    $group->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/albums/human'));
    $mws = $route->middlewares();
    expect(count($mws))->toBe(1);
    expect($mws[0])->toBeInstanceOf(TestMiddleware2::class);

    $route = $router->match($this->request(method: 'GET', url: '/albums/home'));
    $mws = $route->middlewares();
    expect(count($mws))->toBe(2);
    expect($mws[0])->toBeInstanceOf(TestMiddleware2::class);
    expect($mws[1])->toBeInstanceOf(TestMiddleware3::class);
});
