<?php

declare(strict_types=1);

use Conia\Chuck\Exception\HttpMethodNotAllowed;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Exception\ValueError;
use Conia\Chuck\Group;
use Conia\Chuck\Route;
use Conia\Chuck\Router;
use Conia\Chuck\Tests\Fixtures\TestController;
use Conia\Chuck\Tests\Fixtures\TestEndpoint;
use Conia\Chuck\Tests\Fixtures\TestMiddleware2;
use Conia\Chuck\Tests\Fixtures\TestMiddleware3;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);

test('Matching :: named', function () {
    $router = new Router();
    $index = new Route('/', fn () => null, 'index');
    $router->addRoute($index);

    $group = new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->addRoute(Route::get('/home', "{$ctrl}::albumHome", 'home'));
        $group->addRoute(Route::get('/{name}', "{$ctrl}::albumName", 'name'));
        $group->addRoute(Route::get('', "{$ctrl}::albumList", 'list'));
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

        $group->addRoute(Route::get('/home', "{$ctrl}::albumHome"));
        $group->addRoute(Route::get('/{name}', "{$ctrl}::albumName"));
        $group->addRoute(Route::get('', "{$ctrl}::albumList"));
    });
    $group->create($router);

    expect($router->match($this->request(method: 'GET', url: ''))->name())->toBe('');
    expect($router->match($this->request(method: 'GET', url: '/albums/symbolic'))->name())->toBe('');
    expect($router->match($this->request(method: 'GET', url: '/albums/home'))->name())->toBe('');
    expect($router->match($this->request(method: 'GET', url: '/albums'))->name())->toBe('');
});


test('Matching :: with helper methods', function () {
    $router = new Router();
    $index = new Route('/', fn () => null);
    $router->addRoute($index);

    $group = new Group('/helper', function (Group $group) {
        $ctrl = TestController::class;

        $group->get('/get', "{$ctrl}::albumHome", 'getroute');
        $group->post('/post', "{$ctrl}::albumHome", 'postroute');
        $group->put('/put', "{$ctrl}::albumHome", 'putroute');
        $group->patch('/patch', "{$ctrl}::albumHome", 'patchroute');
        $group->delete('/delete', "{$ctrl}::albumHome", 'deleteroute');
        $group->options('/options', "{$ctrl}::albumHome", 'optionsroute');
        $group->head('/head', "{$ctrl}::albumHome", 'headroute');
        $group->route('/route', "{$ctrl}::albumHome", 'allroute');
    }, 'helper:');
    $group->create($router);

    expect($router->match($this->request(method: 'GET', url: '/helper/get'))->name())->toBe('helper:getroute');
    expect($router->match($this->request(method: 'POST', url: '/helper/post'))->name())->toBe('helper:postroute');
    expect($router->match($this->request(method: 'PUT', url: '/helper/put'))->name())->toBe('helper:putroute');
    expect($router->match($this->request(method: 'PATCH', url: '/helper/patch'))->name())->toBe('helper:patchroute');
    expect($router->match($this->request(method: 'DELETE', url: '/helper/delete'))->name())->toBe('helper:deleteroute');
    expect($router->match(
        $this->request(method: 'OPTIONS', url: '/helper/options')
    )->name())->toBe('helper:optionsroute');
    expect($router->match(
        $this->request(method: 'HEAD', url: '/helper/head')
    )->name())->toBe('helper:headroute');
    expect($router->match($this->request(method: 'GET', url: '/helper/route'))->name())->toBe('helper:allroute');
    expect($router->match($this->request(method: 'HEAD', url: '/helper/route'))->name())->toBe('helper:allroute');
    // raises not allowed
    $router->match($this->request(method: 'GET', url: '/helper/delete'));
})->throws(HttpMethodNotAllowed::class);


test('Renderer', function () {
    $router = new Router();

    $group = (new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->addRoute(Route::get('', "{$ctrl}::albumList"));

        // overwrite group renderer
        $group->addRoute(Route::get('/home', "{$ctrl}::albumHome")->render('template:home.php'));

        $group->addRoute(Route::get('/{name}', "{$ctrl}::albumName"));
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
        $group->addRoute(Route::get('-list', 'albumList', 'list'));
    }, 'albums-'))->controller(TestController::class);
    $group->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/albums-list'));
    expect($route->name())->toBe('albums-list');
    expect($route->view())->toBe([TestController::class, 'albumList']);
});

test('Endpoint in group', function () {
    $router = new Router();
    $index = new Route('/', fn () => null);
    $router->addRoute($index);

    $group = (new Group('/media', function (Group $group) {
        $group->endpoint('/albums', TestEndpoint::class, 'id')->name('albums')->add();
    }, 'media-'));
    $group->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/media/albums/666'));
    expect($route->name())->toBe('media-albums-get');
    expect($route->view())->toBe([TestEndpoint::class, 'get']);
    expect($route->args())->toBe(['id' => '666']);
});


test('Nested groups', function () {
    $router = new Router();

    (new Group('/media', function (Group $group) {
        // Create using ::group - will not be created immediately
        $group->group('/music', function (Group $group) {
            // Create using ::addGroup - will internally be created immediately
            $group->addGroup((new Group('/albums', function (Group $group) {
                // Create using ::group shortcut and create immediately
                $group->group('/songs', function (Group $group) {
                    // Create  in place - checks if it skips already created groups
                    $group->endpoint('/times', TestEndpoint::class, 'id')
                        ->name('times')
                        ->middleware('times-middleware')
                        ->add();
                }, 'songs-')->middleware('songs-middleware')->create($group);
            }, 'albums-'))->middleware('albums-middleware'));
        }, 'music-');
    }, 'media-'))->middleware('media-middleware')->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/media/music/albums/songs/times/666'));
    expect($route->name())->toBe('media-music-albums-songs-times-get');
    expect($route->view())->toBe([TestEndpoint::class, 'get']);
    expect($route->pattern())->toBe('/media/music/albums/songs/times/{id}');
    expect($route->args())->toBe(['id' => '666']);
    expect($route->getMiddleware())->toBe([
        'media-middleware', 'albums-middleware', 'songs-middleware', 'times-middleware',
    ]);
});


test('Controller prefixing error using closure', function () {
    $router = new Router();

    $group = (new Group('/albums', function (Group $group) {
        $group->addRoute(
            Route::get('-list', function () {
            })
        );
    }))->controller(TestController::class);
    $group->create($router);
})->throws(ValueError::class, 'Cannot add controller');


test('Controller prefixing error using endpoint', function () {
    $router = new Router();

    $group = (new Group('/media', function (Group $group) {
        $group->endpoint('/albums', TestEndpoint::class, 'id')->name('albums')->add();
    }))->controller(TestController::class);
    $group->create($router);
})->throws(ValueError::class, 'Cannot add controller');


test('Middleware', function () {
    $router = new Router();

    $group = (new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;

        $group->addRoute(Route::get('', "{$ctrl}::albumList"));
        $group->addRoute(Route::get('/home', "{$ctrl}::albumHome")->middleware(new TestMiddleware3()));
        $group->addRoute(Route::get('/{name}', "{$ctrl}::albumName"));
    }))->middleware(new TestMiddleware2());
    $group->create($router);

    $route = $router->match($this->request(method: 'GET', url: '/albums/human'));
    $middleware = $route->getMiddleware();
    expect(count($middleware))->toBe(1);
    expect($middleware[0])->toBeInstanceOf(TestMiddleware2::class);

    $route = $router->match($this->request(method: 'GET', url: '/albums/home'));
    $middleware = $route->getMiddleware();
    expect(count($middleware))->toBe(2);
    expect($middleware[0])->toBeInstanceOf(TestMiddleware2::class);
    expect($middleware[1])->toBeInstanceOf(TestMiddleware3::class);
});


test('Fail without calling create before', function () {
    $group = new Group('/albums', function (Group $group) {
    }, 'test:');
    $group->addRoute(Route::get('/', fn () => ''));
})->throws(RuntimeException::class, 'RouteAdder not set');
