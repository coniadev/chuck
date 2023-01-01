<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\MiddlewareWrapper;
use Conia\Chuck\Tests\Fixtures\{
    TestMiddleware1,
    TestMiddleware2,
};

uses(TestCase::class);

test('Index matching', function () {
    $route = new Route('/', fn () => null);

    expect($route->match('/'))->toBe($route);
    expect($route->match('/rick'))->toBe(null);
});


test('Simple matching', function () {
    $route = new Route('/chuck', fn () => null);

    expect($route->match('/chuck'))->toBe($route);
    expect($route->match('/rick'))->toBe(null);

    // Definition without leading slash
    $route = new Route('chuck/and/rick', fn () => null);

    expect($route->match('/chuck/and/rick'))->toBe($route);
    expect($route->match('/chuck'))->toBe(null);
});


test('Parameter matching', function () {
    $route = new Route('/album/{name}', fn () => null);

    expect($route->match('/album/leprosy'))->toBe($route);
    expect($route->args())->toBe(['name' => 'leprosy']);

    $route = new Route('/contributed/{from}/{to}', fn () => null);

    expect($route->match('/contributed/1983/1991'))->toBe($route);
    expect($route->args())->toBe(['from' => '1983', 'to' => '1991']);
});


test('Parameter matching regex', function () {
    $route = new Route('/contributed/{from:\d+}/{to:\d\d\d}', fn () => null);

    expect($route->match('/contributed/1983/1991'))->toBe(null);
    expect($route->match('/contributed/19937/701'))->toBe($route);
    expect($route->args())->toBe(['from' => '19937', 'to' => '701']);

    $route = new Route('/albums/{from:\d{4}}', fn () => null);
    expect($route->match('/albums/1995'))->toBe($route);
    expect($route->match('/albums/521'))->toBe(null);

    $route = new Route('/albums/{from:\d{3,4}}', fn () => null);
    expect($route->match('/albums/2001'))->toBe($route);
    expect($route->match('/albums/127'))->toBe($route);
    expect($route->match('/albums/13'))->toBe(null);

    $route = new Route('/albums/{from:\d{2}}/{to:\d{4,5}}', fn () => null);
    expect($route->match('/albums/aa/bbbb'))->toBe(null);
    expect($route->match('/albums/13/773'))->toBe(null);
    expect($route->match('/albums/457/1709'))->toBe(null);
    expect($route->match('/albums/73/5183'))->toBe($route);
    expect($route->match('/albums/43/93911'))->toBe($route);
    expect($route->args())->toBe(['from' => '43', 'to' => '93911']);

    $route = new Route('/albums{format:\.?(json|xml|)}', fn () => null);
    expect($route->match('/albums'))->toBe($route);
    expect($route->args())->toBe(['format' => '']);
    expect($route->match('/albums.json'))->toBe($route);
    expect($route->args())->toBe(['format' => '.json']);
    expect($route->match('/albums.xml'))->toBe($route);
    expect($route->args())->toBe(['format' => '.xml']);
});


test('Parameter matching brace error I', function () {
    // Invalid escaped left braces
    $route = new Route('/contributed/{from:\{\d+}', fn () => null);
    $route->match('/');
})->throws(ValueError::class);


test('Parameter matching brace error II', function () {
    // Invalid escaped right braces
    $route = new Route('/contributed/{from:\d+\}}', fn () => null);
    $route->match('/');
})->throws(ValueError::class);


test('Parameter matching brace error III', function () {
    // Invalid unbalanced braces
    $route = new Route('/contributed/{from:\d+{1,2}{}', fn () => null);
    $route->match('/');
})->throws(ValueError::class);


test('Url construction :: regular parameters', function () {
    $route = new Route('/contributed/{from:\d+}/{to:\d\d\d}', fn () => null);
    $obj = new class(1991) extends stdClass
    {
        public function __construct(protected int $val)
        {
        }
        public function __toString(): string
        {
            return (string)$this->val;
        }
    };

    expect($route->url(['from' => 1983, 'to' => $obj]))->toBe('/contributed/1983/1991');
    expect($route->url(from: 1983, to: 1991))->toBe('/contributed/1983/1991');
});


test('Url construction :: no parameters', function () {
    $route = new Route('/albums', fn () => null);

    expect($route->url())->toBe('/albums');
    expect($route->url(test: 1))->toBe('/albums');
});


test('Url construction :: invalid call', function () {
    $route = new Route('/albums', fn () => null);

    $route->url(1, 2);
})->throws(InvalidArgumentException::class);


test('Url construction :: invalid parameters', function () {
    $route = new Route('/contributed/{from:\d+}/{to:\d\d\d}', fn () => null);

    $route->url(from: 1983, to: []);
})->throws(InvalidArgumentException::class);


test('Route prefix', function () {
    $route = Route::get('/albums', fn () => 'chuck')->prefix(pattern: 'api');
    expect($route->match('/api/albums'))->toBe($route);

    $route = Route::get('albums', fn () => 'chuck')->prefix('api/', 'api::');
    expect($route->name())->toBe('api::albums');

    $route = Route::get('albums', fn () => 'chuck')->prefix(name: 'api::');
    expect($route->match('/albums'))->toBe($route);
    expect($route->name())->toBe('api::albums');
});


test('Route params', function () {
    $route = new Route('/', 'chuck', params: ['option' => true]);

    expect($route->params())->toBe(['option' => true]);
});


test('Get view :: closure', function () {
    $route = new Route('/', fn () => 'chuck');

    expect($route->view()())->toBe('chuck');
});


test('Get view :: string', function () {
    $route = new Route('/', 'chuck');

    expect($route->view())->toBe('chuck');
});


test('Get view :: array', function () {
    $route = new Route('/', [Chuck\Tests\Fixtures\TestController::class, 'textView']);

    expect($route->view())->toBe(['Chuck\Tests\Fixtures\TestController', 'textView']);
});


test('Route name unnamed', function () {
    $route = Route::get('/albums', fn () => 'chuck');

    expect($route->name())->toBe('/albums');
});


test('Route name named', function () {
    $route = Route::get('/albums', fn () => 'chuck', 'albumroute');

    expect($route->name())->toBe('albumroute');
});

test('Route middleware', function () {
    $route = Route::get('/', fn () => 'chuck');
    $route->middleware(new TestMiddleware1());
    $route->middleware(new TestMiddleware2());
    $middlewares = $route->middlewares();

    expect($middlewares[0])->toBeInstanceOf(TestMiddleware1::class);
    expect($middlewares[1])->toBeInstanceOf(MiddlewareWrapper::class);
});
