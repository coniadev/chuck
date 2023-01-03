<?php

declare(strict_types=1);

use Conia\Chuck\Attribute\Render;
use Conia\Chuck\Exception\{ HttpNotFound, HttpServerError, HttpMethodNotAllowed};
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Exception\UnresolvableException;
use Conia\Chuck\Renderer\TemplateRenderer;
use Conia\Chuck\Request;
use Conia\Chuck\Response\Response;
use Conia\Chuck\Routing\{Router, Route, Group};
use Conia\Chuck\Tests\Fixtures\TestController;
use Conia\Chuck\Tests\Fixtures\TestControllerWithRequest;
use Conia\Chuck\Tests\Fixtures\TestMiddleware1;
use Conia\Chuck\Tests\Setup\{TestCase, C};

uses(TestCase::class);


test('Matching', function () {
    $router = new Router();
    $index = new Route('/', fn () => null, 'index');
    $router->addRoute($index);
    $albums = new Route('/albums', fn () => null);
    $router->addRoute($albums);
    $router->addGroup(new Group('/albums', function (Group $group) {
        $ctrl = TestController::class;
        $group->addRoute(Route::get('/{name}', "$ctrl::albumName"));
    }));

    expect($router->match($this->request(method: 'GET', url: ''))->name())->toBe('index');

    expect($router->match($this->request(method: 'GET', url: '')))->toBe($index);
    expect($router->match($this->request(method: 'GET', url: '/albums')))->toBe($albums);
    expect($router->match($this->request(method: 'GET', url: '/albums?q=Symbolic')))->toBe($albums);
    expect($router->match($this->request(method: 'GET', url: '/albums/name'))->name())->toBe('/albums/{name}');

    $router->match($this->request(method: 'GET', url: '/does-not-exist'));
})->throws(HttpNotFound::class);


test('Matching with helpers', function () {
    $router = new Router();
    $index = $router->get('/', fn () => null, 'index');
    $albums = $router->post('/albums', fn () => null);

    expect($router->match($this->request(method: 'GET', url: ''))->name())->toBe('index');
    expect($router->match($this->request(method: 'POST', url: '/albums'))->name())->toBe('/albums');
    expect($router->match($this->request(method: 'GET', url: '')))->toBe($index);
    expect($router->match($this->request(method: 'POST', url: '/albums')))->toBe($albums);

    $router->match($this->request(method: 'GET', url: '/albums'));
})->throws(HttpMethodNotAllowed::class);


test('Generate route url', function () {
    $router = new Router();
    $albums = new Route('albums/{from}/{to}', fn () => null, 'albums');
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


test('Static routes: unnamed', function () {
    $router = new Router();
    $router->addStatic('/static', C::root() . C::DS . 'public' . C::DS . 'static');

    expect($router->staticUrl('/static', 'test.json'))->toBe('/static/test.json');
    expect($router->staticUrl('/static', 'test.json', true))->toMatch('/\?v=[a-f0-9]{8}$/');
    expect($router->staticUrl('/static', 'test.json?exists=true', true))->toMatch('/\?exists=true&v=[a-f0-9]{8}$/');
    expect($router->staticUrl(
        '/static',
        'test.json',
        host: 'https://chuck.local/',
        bust: true,
    ))->toMatch('/https:\/\/chuck.local\/static\/test.json\?v=[a-f0-9]{8}$/');
    // Nonexistent files should not have a cachebuster attached
    expect($router->staticUrl(
        '/static',
        'does-not-exist.json',
        host: 'https://chuck.local/',
        bust: true,
    ))->toMatch('/https:\/\/chuck.local\/static\/does-not-exist.json$/');
});


test('Static routes: named', function () {
    $router = new Router();
    $router->addStatic('/static', C::root() . C::DS . 'public' . C::DS . 'static', 'staticroute');

    expect($router->staticUrl('staticroute', 'test.json'))->toBe('/static/test.json');
});


test('Static routes to nonexistent directory', function () {
    (new Router())->addStatic('/static', C::root() . C::DS . 'fantasy' . C::DS . 'dir');
})->throws(RuntimeException::class, 'does not exist');


test('Static route duplicate named', function () {
    $router = new Router();
    $router->addStatic('/static', C::root() . C::DS . 'public' . C::DS . 'static', 'static');
    $router->addStatic('/anotherstatic', C::root() . C::DS . 'public' . C::DS . 'static', 'static');
})->throws(RuntimeException::class, 'Duplicate static route: static');


test('Static route duplicate unnamed', function () {
    $router = new Router();
    $router->addStatic('/static', C::root() . C::DS . 'public' . C::DS . 'static');
    $router->addStatic('/static', C::root() . C::DS . 'public' . C::DS . 'static');
})->throws(RuntimeException::class, 'Duplicate static route: /static');


test('Dispatch closure', function () {
    $router = new Router();
    $index = new Route('/', fn (Request $request) => $request->response->html('Chuck', 200));
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/'), $this->registry());
    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('Chuck');
});


test('View without renderer returning string', function () {
    $router = new Router();
    $index = new Route('/', fn () => 'Chuck');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/'), $this->registry());
    expect($response)->toBeInstanceOf(Response::class);
    // expect($response->headers()['Content-Type'][0]['value'])->toBe('text/html');
    expect((string)$response->getBody())->toBe('Chuck');
});


test('Dispatch class method returning a string', function () {
    $router = new Router();
    $route = new Route('/text', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    $router->addRoute($route);
    $response = $router->dispatch($this->request(method: 'GET', url: '/text'), $this->registry());

    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('text');
});


test('Dispatch class method returning a stringable', function () {
    $router = new Router();
    $route = new Route('/text', 'Conia\Chuck\Tests\Fixtures\TestController::stringableView');
    $router->addRoute($route);
    $response = $router->dispatch($this->request(method: 'GET', url: '/text'), $this->registry());

    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('Stringable');
});


test('Dispatch class method returing an array with renderer', function () {
    $router = new Router();
    $route = Route::get('/text', [TestController::class, 'arrayView'])->render('json');
    $router->addRoute($route);
    $response = $router->dispatch($this->request(method: 'GET', url: '/text'), $this->registry());

    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('{"success":true}');
});


test('Dispatch invokable class', function () {
    $router = new Router();
    // phpcs:disable
    class ___InvocableClass
    {
        public function __invoke(Request $request)
        {
            return $request->response->html('Schuldiner');
        }
    };
    // phpcs:enable
    $object = new Route('/object', '___InvocableClass');
    $router->addRoute($object);

    $response = $router->dispatch($this->request(method: 'GET', url: '/object'), $this->registry());
    expect($response)->toBeInstanceOf(Response::class);
    expect((string)$response->getBody())->toBe('Schuldiner');
});


test('Dispatch controller with request constructor', function () {
    $router = new Router();
    $index = new Route('/', TestControllerWithRequest::class . '::requestOnly');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/'), $this->registry());
    expect((string)$response->getBody())->toBe('Conia\Chuck\Request');
});


test('Dispatch closure with Render attribute', function () {
    $config = $this->config();
    $config->addRenderer('template', TemplateRenderer::class, $this->templates());

    $router = new Router();
    $index = new Route(
        '/',
        #[Render('template', 'plain', contentType: 'application/xhtml+xml')]
        function () {
            return [];
        }
    );
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/', config: $config), $this->registry());
    expect($this->fullTrim($response->getBody()))->toBe('<p>plain</p>');
});


test('Dispatch nonexistent controller view', function () {
    $router = new Router();
    $index = new Route('/', TestController::class . '::nonexistentView');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/'), $this->registry());
})->throws(HttpServerError::class);


test('Dispatch nonexistent controller', function () {
    $router = new Router();
    $index = new Route('/', NonexisitentTestController::class . '::view');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/'), $this->registry());
})->throws(HttpServerError::class);


test('Dispatch wrong view return type', function () {
    $router = new Router();
    $index = new Route('/', TestControllerWithRequest::class . '::wrongReturnType');
    $router->addRoute($index);
    $router->dispatch($this->request(method: 'GET', url: '/'), $this->registry());
})->throws(RuntimeException::class, 'Cannot determine a response handler');


test('Dispatch missing route', function () {
    $router = new Router();
    $index = new Route('/', TestControllerWithRequest::class . '::wrongReturnType');
    $router->addRoute($index);
    $router->dispatch($this->request(method: 'GET', url: '/wrong'), $this->registry());
})->throws(HttpNotFound::class);


test('Dispatch view with route params', function () {
    $router = new Router();
    $index = (new Route('/{string}/{float}-{int}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic/7.13-23'), $this->registry());
    expect($router->getRoute())->toBeInstanceOf(Route::class);
    expect((string)$response->getBody())->toBe(
        '{"string":"symbolic","float":7.13,"int":23,"request":"Conia\\\\Chuck\\\\Request"}'
    );
});


test('Dispatch view with default value params', function () {
    $index = (new Route('/{string}', TestController::class . '::routeDefaultValueParams'))->render('json');
    $withInt = (new Route('/{string}/{int}', TestController::class . '::routeDefaultValueParams'))->render('json');

    $router = new Router();
    $router->addRoute($index);
    $router->addRoute($withInt);
    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic/17'), $this->registry());

    expect($router->getRoute())->toBeInstanceOf(Route::class);
    expect((string)$response->getBody())->toBe(
        '{"string":"symbolic","int":17}'
    );

    $router = new Router();
    $router->addRoute($index);
    $router->addRoute($withInt);
    $response = $router->dispatch($this->request(method: 'GET', url: '/symbolic'), $this->registry());

    expect($router->getRoute())->toBeInstanceOf(Route::class);
    expect((string)$response->getBody())->toBe(
        '{"string":"symbolic","int":13}'
    );
});


test('Dispatch view with wrong route params', function () {
    $router = new Router();
    $index = (new Route('/{wrong}/{param}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/symbolic/7.13-23'), $this->registry());
})->throws(RuntimeException::class, 'cannot be resolved');


test('Dispatch view with wrong type for int param', function () {
    $router = new Router();
    $index = (new Route('/{string}/{float}-{int}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/symbolic/7.13-wrong'), $this->registry());
})->throws(RuntimeException::class, "Cannot cast 'int' to int");


test('Dispatch view with wrong type for float param', function () {
    $router = new Router();
    $index = (new Route('/{string}/{float}-{int}', TestControllerWithRequest::class . '::routeParams'))->render('json');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/symbolic/wrong-13'), $this->registry());
})->throws(RuntimeException::class, "Cannot cast 'float' to float");


test('Dispatch view with unsupported param', function () {
    $router = new Router();
    $index = (new Route('/{name}', fn (GdImage $name) => $name))->render('json');
    $router->addRoute($index);

    $router->dispatch($this->request(method: 'GET', url: '/symbolic'), $this->registry());
})->throws(UnresolvableException::class, 'unresolvable: GdImage');


test('Access uninitialized route', function () {
    (new Router())->getRoute();
})->throws(RuntimeException::class, 'Route is not initialized');


test('Duplicate route :: named', function () {
    $router = new Router();
    $router->addRoute(new Route('/', fn () => null, 'index'));
    $router->addRoute(new Route('albums', fn () => null, 'index'));
})->throws(RuntimeException::class, 'Duplicate route: index');


test('Duplicate route :: unnamed', function () {
    $router = new Router();
    $router->addRoute(new Route('/albums', fn () => null));
    $router->addRoute(new Route('/albums', fn () => ''));
})->throws(RuntimeException::class, 'Duplicate route: /albums');


test('Dispatch view with route params including request', function () {
    $router = new Router();
    $index = (new Route(
        '/{int}/{string}-{float}',
        TestController::class . '::routeParams'
    ))->render('json');
    $router->addRoute($index);

    $response = $router->dispatch($this->request(method: 'GET', url: '/17/spiritual-healing-23.31'), $this->registry());
    expect((string)$response->getBody())->toBe(
        '{"string":"spiritual-healing","float":23.31,"int":17,"request":"Conia\\\\Chuck\\\\Request"}'
    );
});


test('Middleware add', function () {
    $router = new Router();

    $router->middleware(function (Request $request, callable $next): Response|Request {
        return $next($request);
    });
    $router->middleware(new TestMiddleware1());

    expect(count($router->middlewares()))->toBe(2);
});


test('GET matching', function () {
    $router = new Router();
    $route = Route::get('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
});


test('HEAD matching', function () {
    $router = new Router();
    $route = Route::head('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
});


test('PUT matching', function () {
    $router = new Router();
    $route = Route::put('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'PUT', url: '/')))->toBe($route);
});


test('POST matching', function () {
    $router = new Router();
    $route = Route::post('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
});


test('PATCH matching', function () {
    $router = new Router();
    $route = Route::patch('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'PATCH', url: '/')))->toBe($route);
});


test('DELETE matching', function () {
    $router = new Router();
    $route = Route::delete('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'DELETE', url: '/')))->toBe($route);
});


test('OPTIONS matching', function () {
    $router = new Router();
    $route = Route::options('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'OPTIONS', url: '/')))->toBe($route);
});


test('Matching wrong method', function () {
    $router = new Router();
    $route = Route::get('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
})->throws(HttpMethodNotAllowed::class);


test('Multiple methods matching I', function () {
    $router = new Router();
    $route = Route::get('/', fn () => null)->method('post');
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
    $router->match($this->request(method: 'PUT', url: '/'));
})->throws(HttpMethodNotAllowed::class);


test('Multiple methods matching II', function () {
    $router = new Router();
    $route = (new Route('/', fn () => null))->method('gEt', 'Put');
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'PUT', url: '/')))->toBe($route);
    $router->match($this->request(method: 'POST', url: '/'));
})->throws(HttpMethodNotAllowed::class);


test('Multiple methods matching III', function () {
    $router = new Router();
    $route = (new Route('/', fn () => null))->method('get')->method('head');
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
    $router->match($this->request(method: 'POST', url: '/'));
})->throws(HttpMethodNotAllowed::class);


test('All methods matching', function () {
    $router = new Router();
    $route = new Route('/', fn () => null);
    $router->addRoute($route);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'HEAD', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'POST', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'PUT', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'PATCH', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'DELETE', url: '/')))->toBe($route);
    expect($router->match($this->request(method: 'OPTIONS', url: '/')))->toBe($route);
});


test('Same pattern multiple methods', function () {
    $router = new Router();
    $puthead = (new Route('/', fn () => null, 'puthead'))->method('HEAD', 'Put');
    $router->addRoute($puthead);
    $get = (new Route('/', fn () => null, 'get'))->method('GET');
    $router->addRoute($get);

    expect($router->match($this->request(method: 'GET', url: '/')))->toBe($get);
    expect($router->match($this->request(method: 'PUT', url: '/')))->toBe($puthead);
    expect($router->match($this->request(method: 'HEAD', url: '/')))->toBe($puthead);
    $router->match($this->request(method: 'POST', url: '/'));
})->throws(HttpMethodNotAllowed::class);
