<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Route;

uses(TestCase::class);

test('Index matching', function () {
    $route = new Route('index', '/', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'GET', url: '/rick')))->toBe(null);
});


test('Simple matching', function () {
    $route = new Route('chuck', '/chuck', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/chuck')))->toBe($route);
    expect($route->match($this->request(method: 'GET', url: '/chuck?is_evil=no')))->toBe($route);
    expect($route->match($this->request(method: 'GET', url: '/rick')))->toBe(null);

    $route = new Route('chuck', '/chuck/and/rick', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/chuck/and/rick')))->toBe($route);
    expect($route->match($this->request(method: 'GET', url: '/chuck')))->toBe(null);
});


test('Parameter matching', function () {
    $route = new Route('album', '/album/{name}', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/album/leprosy')))->toBe($route);
    expect($route->args())->toBe(['name' => 'leprosy']);

    $route = new Route('contrib', '/contributed/{from}/{to}', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/contributed/1983/1991')))->toBe($route);
    expect($route->args())->toBe(['from' => '1983', 'to' => '1991']);
});


test('Parameter matching regex', function () {
    $route = new Route('contrib', '/contributed/{from:\d+}/{to:\d\d\d}', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/contributed/1983/1991')))->toBe(null);
    expect($route->match($this->request(method: 'GET', url: '/contributed/13731/666')))->toBe($route);
    expect($route->args())->toBe(['from' => '13731', 'to' => '666']);
});


test('Url construction :: regular parameters', function () {
    $route = new Route('contrib', '/contributed/{from:\d+}/{to:\d\d\d}', fn () => null);

    expect($route->getUrl(['from' => '1983', 'to' => '1991']))->toBe('/contributed/1983/1991');
    expect($route->getUrl(from: 1983, to: 1991))->toBe('/contributed/1983/1991');
});


test('Url construction :: no parameters', function () {
    $route = new Route('albums', '/albums', fn () => null);

    expect($route->getUrl())->toBe('/albums');
    expect($route->getUrl(test: 1))->toBe('/albums');
});


test('Url construction :: invalid call', function () {
    $route = new Route('albums', '/albums', fn () => null);

    expect($route->getUrl(1, 2))->toBe('/albums');
})->throws(\InvalidArgumentException::class);


test('GET matching', function () {
    $route = Route::get('index', '/', fn () => null);

    expect($route->match($this->request(method: 'POST', url: '/')))->toBe(null);
    expect($route->match($this->request(method: 'GET', url: '/')))->toBe($route);
});


test('HEAD matching', function () {
    $route = Route::head('index', '/', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/')))->toBe(null);
    expect($route->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
});


test('POST matching', function () {
    $route = Route::post('index', '/', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/')))->toBe(null);
    expect($route->match($this->request(method: 'POST', url: '/')))->toBe($route);
});


test('PUT matching', function () {
    $route = Route::put('index', '/', fn () => null);

    expect($route->match($this->request(method: 'POST', url: '/')))->toBe(null);
    expect($route->match($this->request(method: 'PUT', url: '/')))->toBe($route);
});


test('PATCH matching', function () {
    $route = Route::patch('index', '/', fn () => null);

    expect($route->match($this->request(method: 'PUT', url: '/')))->toBe(null);
    expect($route->match($this->request(method: 'PATCH', url: '/')))->toBe($route);
});


test('DELETE matching', function () {
    $route = Route::delete('index', '/', fn () => null);

    expect($route->match($this->request(method: 'POST', url: '/')))->toBe(null);
    expect($route->match($this->request(method: 'DELETE', url: '/')))->toBe($route);
});


test('OPTIONS matching', function () {
    $route = Route::options('index', '/', fn () => null);

    expect($route->match($this->request(method: 'PATCH', url: '/')))->toBe(null);
    expect($route->match($this->request(method: 'OPTIONS', url: '/')))->toBe($route);
});


test('Multiple methods matching I', function () {
    $route = Route::get('index', '/', fn () => null)->method('post');

    expect($route->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'POST', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'PUT', url: '/')))->toBe(null);
});


test('Multiple methods matching II', function () {
    $route = (new Route('index', '/', fn () => null))->method('gEt',  'Put');

    expect($route->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'PUT', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'POST', url: '/')))->toBe(null);
});


test('Multiple methods matching III', function () {
    $route = (new Route('index', '/', fn () => null))->method('get')->method('head');

    expect($route->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'POST', url: '/')))->toBe(null);
});


test('All methods matching', function () {
    $route = new Route('index', '/', fn () => null);

    expect($route->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'POST', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'PUT', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'PATCH', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'DELETE', url: '/')))->toBe($route);
    expect($route->match($this->request(method: 'OPTIONS', url: '/')))->toBe($route);
});


test('Get view :: closure', function () {
    $route = new Route('index', '/', fn () => 'chuck');

    expect($route->view()())->toBe('chuck');
});


test('Get view :: string', function () {
    $route = new Route('index', '/', 'chuck');

    expect($route->view())->toBe('chuck');
});
