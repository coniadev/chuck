<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Tests\Fixtures\TestMiddleware1;
use Chuck\Tests\Fixtures\TestController;
use Chuck\Tests\Fixtures\TestControllerWithRequest;
use Chuck\{Request, Response};
use Chuck\Routing\{Router, Route, Group};
use Chuck\Error\{HttpNotFound, HttpServerError, HttpMethodNotAllowed};

uses(TestCase::class);


test('Matching', function () {
    $router = new Router();
    $index = new Route('index', '/', fn () => null);
    $router->addRoute($index);
    $albums = new Route('albums', '/albums', fn () => null);
    $router->addRoute($albums);
    $router->addGroup(Group::new('albums:', '/albums', function (Group $group) {
        $ctrl = TestController::class;
        $group->add(Route::get('name', '/{name}', "$ctrl::albumName"));
    }));

    expect($router->match($this->request(method: 'GET', url: ''))->name())->toBe('index');

    expect($router->match($this->request(method: 'GET', url: '')))->toBe($index);
    expect($router->match($this->request(method: 'GET', url: '/albums')))->toBe($albums);
    expect($router->match($this->request(method: 'GET', url: '/albums?q=Symbolic')))->toBe($albums);
    expect($router->match($this->request(method: 'GET', url: '/albums/name'))->name())->toBe('albums:name');

    $router->match($this->request(method: 'GET', url: '/does-not-exist'));
})->throws(HttpNotFound::class);


test('Generate route url', function () {
    $router = new Router();
    $albums = new Route('albums', 'albums/{from}/{to}', fn () => null);
    $router->addRoute($albums);

    expect($router->routeUrl('albums', from: 1990, to: 1995))->toBe('/albums/1990/1995');
    $this->enableHttps();
    expect($router->routeUrl('albums', ['from' => 1988, 'to' => 1991]))->toBe('/albums/1988/1991');
    $this->disableHttps();
});


test('Fail to generate route url', function () {
    $router = new Router();
    $router->routeUrl('fantasy');
})->throws(RuntimeException::class, 'Route not found');


test('Static routes', function () {
    $router = new Router();
    $router->addStatic('static', '/static', C::root() . C::DS . 'public' . C::DS . 'static');

    expect($router->staticUrl('static', 'test.json'))->toBe('/static/test.json');
    expect($router->staticUrl('static', 'test.json', true))->toMatch('/\?v=[a-f0-9]{8}$/');
    expect($router->staticUrl('static', 'test.json?exists=true', true))->toMatch('/\?exists=true&v=[a-f0-9]{8}$/');
    expect($router->staticUrl(
        'static',
        'test.json',
        host: 'https://chuck.local/',
        bust: true,
    ))->toMatch('/https:\/\/chuck.local\/static\/test.json\?v=[a-f0-9]{8}$/');
    // Nonexistent files should not have a cachebuster attached
    expect($router->staticUrl(
        'static',
        'does-not-exist.json',
        host: 'https://chuck.local/',
        bust: true,
    ))->toMatch('/https:\/\/chuck.local\/static\/does-not-exist.json$/');
});


test('Static routes to nonexistent directory', function () {
    (new Router())->addStatic('static', '/static', C::root() . C::DS . 'fantasy' . C::DS . 'dir');
})->throws(RuntimeException::class, 'does not exist');


test('Dispatch closure', function () {
    $router = new Router();
    $index = new Route('index', '/', fn (Request $request) => new Response(200, 'Chuck'));
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/'));
    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('Chuck');
});


test('Dispatch class method as string', function () {
    $router = new Router();
    $route = new Route('text', '/text', 'Chuck\Tests\Fixtures\TestController::textView');
    $router->addRoute($route);
    $response = $router->dispatch($this->request(method: 'GET', url: '/text'));

    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('success');
});


test('Dispatch class method as array', function () {
    $router = new Router();
    $route = Route::get('text', '/text', [TestController::class, 'arrayView'])->render('json');
    $router->addRoute($route);
    $response = $router->dispatch($this->request(method: 'GET', url: '/text'));

    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('{"success":true}');
});


test('Dispatch invokable class', function () {
    $router = new Router();
    class ___InvocableClass
    {
        public function __invoke(Request $request)
        {
            return new Response(200, 'Schuldiner');
        }
    };
    $object = new Route('object', '/object', '___InvocableClass');
    $router->addRoute($object);

    $response = $router->dispatch($this->request(method: 'GET', url: '/object'));
    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('Schuldiner');
});


test('Dispatch controller with request constructor', function () {
    $router = new Router();
    $index = new Route('index', '/', TestControllerWithRequest::class . '::requestOnly');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/'));
    expect((string)$response->getBody())->toBe('Chuck\Request');
});


test('Dispatch nonexistent controller view', function () {
    $router = new Router();
    $index = new Route('index', '/', TestController::class . '::nonexistentView');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/'));
})->throws(HttpServerError::class);


test('Dispatch nonexistent controller', function () {
    $router = new Router();
    $index = new Route('index', '/', NonexisitentTestController::class . '::view');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/'));
})->throws(HttpServerError::class);


test('Dispatch wrong view return type', function () {
    $router = new Router();
    $index = new Route('index', '/', TestControllerWithRequest::class . '::wrongReturnType');
    $router->addRoute($index);
    $router->dispatch($this->request(method: 'GET', url: '/'));
})->throws(RuntimeException::class, 'Cannot determine a handler');


test('Dispatch missing route', function () {
    $router = new Router();
    $index = new Route('index', '/', TestControllerWithRequest::class . '::wrongReturnType');
    $router->addRoute($index);
    $router->dispatch($this->request(method: 'GET', url: '/wrong'));
})->throws(HttpNotFound::class);


test('Dispatch view with route params', function () {
    $router = new Router();
    $index = (new Route('params', '/{string}/{float}-{int}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic/7.13-23'));
    expect($router->getRoute())->toBeInstanceOf(Route::class);
    expect((string)$response->getBody())->toBe(
        '{"string":"symbolic","float":7.13,"int":23,"request":"Chuck\\\\Request"}'
    );
});


test('Dispatch view with wrong route params', function () {
    $router = new Router();
    $index = (new Route('params', '/{wrong}/{param}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic/7.13-23'));
})->throws(RuntimeException::class, 'cannot be resolved');


test('Dispatch view with wrong type for int param', function () {
    $router = new Router();
    $index = (new Route('params', '/{string}/{float}-{int}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic/7.13-wrong'));
})->throws(RuntimeException::class, "Cannot cast 'int' to int");


test('Dispatch view with wrong type for float param', function () {
    $router = new Router();
    $index = (new Route('params', '/{string}/{float}-{int}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic/wrong-13'));
})->throws(RuntimeException::class, "Cannot cast 'float' to float");


test('Dispatch view with unsupported param', function () {
    $router = new Router();
    $index = (new Route('params', '/{name}', fn (GdImage $name) => $name))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic'));
})->throws(RuntimeException::class, 'is not supported');


test('Access uninitialized route', function () {
    (new Router())->getRoute();
})->throws(RuntimeException::class, 'Route is not initialized');


test('Duplicate route name', function () {
    $router = new Router();
    $router->addRoute(new Route('index', '/', fn () => null));
    $router->addRoute(new Route('index', 'albums', fn () => null));
})->throws(RuntimeException::class, 'Duplicate route name');


test('Dispatch view with route params including request', function () {
    $router = new Router();
    $index = (new Route(
        'params',
        '/{int}/{string}-{float}',
        TestController::class . '::routeParams'
    ))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/17/spiritual-healing-23.31'));
    expect((string)$response->getBody())->toBe(
        '{"string":"spiritual-healing","float":23.31,"int":17,"request":"Chuck\\\\Request"}'
    );
});


test('Middleware add', function () {
    $router = new Router();

    $router->addMiddleware(function (Request $request, callable $next): Response|Request {
        return $next($request);
    });
    $router->addMiddleware(new TestMiddleware1());

    expect(count($router->middlewares()))->toBe(2);
});


test('GET matching', function () {
    $router = new Router();
    $route = Route::get('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
});


test('HEAD matching', function () {
    $router = new Router();
    $route = Route::head('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
});


test('PUT matching', function () {
    $router = new Router();
    $route = Route::put('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'PUT', url: '/')))->toBe($route);
});


test('POST matching', function () {
    $router = new Router();
    $route = Route::post('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
});


test('PATCH matching', function () {
    $router = new Router();
    $route = Route::patch('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'PATCH', url: '/')))->toBe($route);
});


test('DELETE matching', function () {
    $router = new Router();
    $route = Route::delete('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'DELETE', url: '/')))->toBe($route);
});


test('OPTIONS matching', function () {
    $router = new Router();
    $route = Route::options('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'OPTIONS', url: '/')))->toBe($route);
});


test('Matching wrong method', function () {
    $router = new Router();
    $route = Route::get('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
})->throws(HttpMethodNotAllowed::class);


test('Multiple methods matching I', function () {
    $router = new Router();
    $route = Route::get('index', '/', fn () => null)->method('post');
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
    $router->match($this->request(method: 'PUT', url: '/'));
})->throws(HttpMethodNotAllowed::class);


test('Multiple methods matching II', function () {
    $router = new Router();
    $route = (new Route('index', '/', fn () => null))->method('gEt',  'Put');
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'PUT', url: '/')))->toBe($route);
    $router->match($this->request(method: 'POST', url: '/'));
})->throws(HttpMethodNotAllowed::class);


test('Multiple methods matching III', function () {
    $router = new Router();
    $route = (new Route('index', '/', fn () => null))->method('get')->method('head');
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
    $router->match($this->request(method: 'POST', url: '/'));
})->throws(HttpMethodNotAllowed::class);


test('All methods matching', function () {
    $router = new Router();
    $route = new Route('index', '/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'PUT', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'PATCH', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'DELETE', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'OPTIONS', url: '/')))->toBe($route);
});
