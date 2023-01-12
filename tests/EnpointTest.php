<?php

declare(strict_types=1);

use Conia\Chuck\Routing\Endpoint;
use Conia\Chuck\Routing\Router;
use Conia\Chuck\Tests\Fixtures\TestEndpoint;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Endpoint with defaults', function () {
    $router = new Router();
    (new Endpoint($router, '/endpoints', TestEndpoint::class, 'id'))->add();

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'deleteList']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoints/13'));
    expect($route->pattern())->toBe('/endpoints/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'delete']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'GET', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'list']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'GET', url: '/endpoints/13'));
    expect($route->pattern())->toBe('/endpoints/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'get']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'headList']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoints/13'));
    expect($route->pattern())->toBe('/endpoints/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'head']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'optionsList']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoints/13'));
    expect($route->pattern())->toBe('/endpoints/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'options']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'PATCH', url: '/endpoints/13'));
    expect($route->pattern())->toBe('/endpoints/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'patch']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'POST', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'post']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'PUT', url: '/endpoints/13'));
    expect($route->pattern())->toBe('/endpoints/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'put']);
    expect($route->args())->toBe(['id' => '13']);
});


test('Endpoint with plural/singular', function () {
    $router = new Router();
    (new Endpoint($router, ['/endpoints', '/endpoint'], TestEndpoint::class, 'id'))->add();

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'deleteList']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoint/13'));
    expect($route->pattern())->toBe('/endpoint/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'delete']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'GET', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'list']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'GET', url: '/endpoint/13'));
    expect($route->pattern())->toBe('/endpoint/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'get']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'headList']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoint/13'));
    expect($route->pattern())->toBe('/endpoint/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'head']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'optionsList']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoint/13'));
    expect($route->pattern())->toBe('/endpoint/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'options']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'PATCH', url: '/endpoint/13'));
    expect($route->pattern())->toBe('/endpoint/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'patch']);
    expect($route->args())->toBe(['id' => '13']);

    $route = $router->match($this->request(method: 'POST', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'post']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'PUT', url: '/endpoint/13'));
    expect($route->pattern())->toBe('/endpoint/{id}');
    expect($route->view())->toBe([TestEndpoint::class, 'put']);
    expect($route->args())->toBe(['id' => '13']);
});


test('Endpoint with name', function () {
    $router = new Router();
    (new Endpoint($router, '/endpoints', TestEndpoint::class, 'id'))->name('albums')->add();

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoints'));
    expect($route->name())->toBe('albums_deleteList');

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoints/13'));
    expect($route->name())->toBe('albums_delete');

    $route = $router->match($this->request(method: 'GET', url: '/endpoints'));
    expect($route->name())->toBe('albums_list');

    $route = $router->match($this->request(method: 'GET', url: '/endpoints/13'));
    expect($route->name())->toBe('albums_get');

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoints'));
    expect($route->name())->toBe('albums_headList');

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoints/13'));
    expect($route->name())->toBe('albums_head');

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoints'));
    expect($route->name())->toBe('albums_optionsList');

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoints/13'));
    expect($route->name())->toBe('albums_options');

    $route = $router->match($this->request(method: 'PATCH', url: '/endpoints/13'));
    expect($route->name())->toBe('albums_patch');

    $route = $router->match($this->request(method: 'POST', url: '/endpoints'));
    expect($route->name())->toBe('albums_post');

    $route = $router->match($this->request(method: 'PUT', url: '/endpoints/13'));
    expect($route->name())->toBe('albums_put');
});


test('Endpoint with attributes', function () {
    $router = new Router();
    (new Endpoint($router, '/endpoints', TestEndpoint::class, 'id'))->attrs(cat: 'albums')->add();

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoints'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'DELETE', url: '/endpoints/13'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'GET', url: '/endpoints'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'GET', url: '/endpoints/13'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoints'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'HEAD', url: '/endpoints/13'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoints'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'OPTIONS', url: '/endpoints/13'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'PATCH', url: '/endpoints/13'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'POST', url: '/endpoints'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);

    $route = $router->match($this->request(method: 'PUT', url: '/endpoints/13'));
    expect($route->getAttrs())->toBe(['cat' => 'albums']);
});


test('Endpoint default renderer', function () {
    $router = new Router();
    (new Endpoint($router, '/endpoint', TestEndpoint::class, 'id'))->add();
    $route = $router->match($this->request(method: 'GET', url: '/endpoint'));
    $rendererConfig = $route->getRenderer();

    expect($rendererConfig->type)->toBe('json');
    expect($rendererConfig->args)->toBe([]);
});


test('Endpoint set renderer', function () {
    $router = new Router();
    (new Endpoint($router, '/endpoint', TestEndpoint::class, 'id'))->render('text', 1, 'test')->add();
    $route = $router->match($this->request(method: 'GET', url: '/endpoint'));
    $rendererConfig = $route->getRenderer();

    expect($rendererConfig->type)->toBe('text');
    expect($rendererConfig->args)->toBe([1, 'test']);
});


test('Endpoint with multiple args', function () {
    $router = new Router();
    (new Endpoint($router, '/endpoints', TestEndpoint::class, ['id', 'category']))->add();

    $route = $router->match($this->request(method: 'POST', url: '/endpoints'));
    expect($route->pattern())->toBe('/endpoints');
    expect($route->view())->toBe([TestEndpoint::class, 'post']);
    expect($route->args())->toBe([]);

    $route = $router->match($this->request(method: 'PUT', url: '/endpoints/13/albums'));
    expect($route->pattern())->toBe('/endpoints/{id}/{category}');
    expect($route->view())->toBe([TestEndpoint::class, 'put']);
    expect($route->args())->toBe(['id' => '13', 'category' => 'albums']);
});
