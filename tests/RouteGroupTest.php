<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Tests\Fixtures\{
    TestController,
    TestMiddleware1,
    TestMiddleware2,
    TestMiddleware3
};
use Chuck\Routing\{Router, Route, Group};

uses(TestCase::class);


test('Matching', function () {
    $router = new Router();
    $index = new Route('index', '/', fn () => null);
    $router->addRoute($index);

    $group = Group::new('albums:', '/albums', function (Group $group) {
        $ctrl = TestController::class;

        // overwrite group renderer
        $group->add(Route::get('home', '/home', "$ctrl::albumHome"));
        $group->add(Route::get('name', '/{name}', "$ctrl::albumName"));
        $group->add(Route::get('list', '', "$ctrl::albumList"));
    });
    $group->create($router);

    expect($router->match($this->request(method: 'GET', url: ''))->name())->toBe('index');
    expect($router->match($this->request(method: 'GET', url: '/albums/symbolic'))->name())->toBe('albums:name');
    expect($router->match($this->request(method: 'GET', url: '/albums/home'))->name())->toBe('albums:home');
    expect($router->match($this->request(method: 'GET', url: '/albums'))->name())->toBe('albums:list');
    expect($router->routeUrl('albums:name', name: 'symbolic'))->toBe('/albums/symbolic');
});


test('Renderer', function () {
    $router = new Router();

    $group = Group::new('albums:', '/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->add(Route::get('list', '', "$ctrl::albumList"));

        // overwrite group renderer
        $group->add(Route::get('home', '/home', "$ctrl::albumHome")->render('template:home.php'));

        $group->add(Route::get('name', '/{name}', "$ctrl::albumName"));
    })->render('json');
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
    $index = new Route('index', '/', fn () => null);
    $router->addRoute($index);

    $group = Group::new('albums-', '/albums', function (Group $group) {
        $group->add(Route::get('list', '-list', '::albumList'));
    })->controller(TestController::class);
    $group->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/albums-list'));
    expect($route->name())->toBe('albums-list');
    expect($route->view())->toBe(TestController::class . '::albumList');
});


test('Controller prefixing error', function () {
    $router = new Router();

    $group = Group::new('albums-', '/albums', function (Group $group) {
        $group->add(Route::get('list', '-list', function () {
        }));
    })->controller(TestController::class);
    $group->create($router);
})->throws(ValueError::class, 'Cannot add controller');


test('Middleware', function () {
    $router = new Router();
    $router->addMiddleware(new TestMiddleware1());

    $group = Group::new('albums:', '/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->add(Route::get('list', '', "$ctrl::albumList"));
        $group->add(Route::get('home', '/home', "$ctrl::albumHome")->middleware(new TestMiddleware3()));
        $group->add(Route::get('name', '/{name}', "$ctrl::albumName"));
    })->middleware(new TestMiddleware2());
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
