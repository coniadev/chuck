<?php

declare(strict_types=1);

use Chuck\ConfigInterface;
use Chuck\Error\ExitException;
use Chuck\File;
use Chuck\Renderer\{JsonRenderer, TemplateRenderer};
use Chuck\Request;
use Chuck\ResponseFactory;
use Chuck\Response\ResponseInterface;
use Chuck\Response\Response;
use Chuck\Routing\Route;
use Chuck\Routing\RouteInterface;
use Chuck\Routing\Router;
use Chuck\Routing\RouterInterface;
use Chuck\Tests\Setup\{TestCase, C};


uses(TestCase::class);


test('Helper methods', function () {
    $request = $this->request();

    expect($request->config())->toBeInstanceOf(ConfigInterface::class);
    expect($request->router())->toBeInstanceOf(RouterInterface::class);
    expect($request->response)->toBeInstanceOf(ResponseFactory::class);
    expect($request->response->html('Chuck'))->toBeInstanceOf(ResponseInterface::class);
    expect($request->method())->toBe('GET');
    expect($request->isMethod('GET'))->toBe(true);
    expect($request->isMethod('POST'))->toBe(false);
});


test('Route property :: initialized', function () {
    $router = new Router();
    $router->addRoute(new Route('/', fn (Request $request) => new Response('Chuck')));
    $request = $this->request(method: 'GET', url: '/', router: $router);
    $router->dispatch($request);

    expect($request->route())->toBeInstanceOf(RouteInterface::class);
});


test('Route method :: uninitialized', function () {
    $request = $this->request();

    expect($request->route())->toBeInstanceOf(RouteInterface::class);
})->throws(RuntimeException::class, 'Route is not initialized');


test('Url helpers', function () {
    $request = $this->request();

    expect($request->url())->toBe('/');
    expect($request->serverUrl())->toBe('http://www.example.com/');

    $this->setUrl('albums?from=1988&to=1991');
    expect($request->url())->toBe('/albums?from=1988&to=1991');
    expect($request->serverUrl())->toBe('http://www.example.com/albums?from=1988&to=1991');
    expect($request->url(stripQuery: true))->toBe('/albums');
    expect($request->serverUrl(stripQuery: true))->toBe('http://www.example.com/albums');
});


test('Generate route url :: named', function () {
    $router = new Router();
    $albums = new Route('albums/{from}/{to}', fn () => null, 'albums');
    $router->addRoute($albums);
    $request = $this->request(router: $router);

    expect($request->routeUrl('albums', from: 1990, to: 1995))->toBe('http://www.example.com/albums/1990/1995');
    expect($request->routeUrl('albums', ['from' => 1988, 'to' => 1991]))->toBe('http://www.example.com/albums/1988/1991');
});


test('Generate route url :: unnamed', function () {
    $router = new Router();
    $albums = new Route('albums/{from}/{to}', fn () => null);
    $router->addRoute($albums);
    $request = $this->request(router: $router);

    expect($request->routeUrl('albums/{from}/{to}', from: 1990, to: 1995))->toBe('http://www.example.com/albums/1990/1995');
    expect($request->routeUrl('albums/{from}/{to}', ['from' => 1988, 'to' => 1991]))->toBe('http://www.example.com/albums/1988/1991');
});


test('Static routes', function () {
    $router = new Router();
    $router->addStatic('/static', C::root() . C::DS . 'public' . C::DS . 'static', 'static');
    $request = $this->request(router: $router);

    expect($request->staticUrl('static', 'test.json'))->toBe('http://www.example.com/static/test.json');
    expect($request->staticUrl('static', 'test.json', true))->toMatch(
        '/http:\/\/www.example.com\/static\/test\.json\?v=[a-f0-9]{8}$/'
    );
    expect($request->staticUrl('static', 'test.json?exists=true', true))->toMatch(
        '/http:\/\/www.example.com\/static\/test\.json\?exists=true&v=[a-f0-9]{8}$/'
    );

    $router = new Router();
    $router->addStatic('/static', C::root() . C::DS . 'public' . C::DS . 'static');
    $request = $this->request(router: $router);

    expect($request->staticUrl('/static', 'test.json'))->toBe('http://www.example.com/static/test.json');
});


test('Request::param', function () {
    $this->set('GET', ['chuck' => 'schuldiner', 'born' => '1967']);
    $this->set('POST', ['first_band' => 'Mantas']);
    $request = $this->request();

    expect($request->param('chuck'))->toBe('schuldiner');
    expect($request->param('born'))->toBe('1967');
    expect($request->param('first_band'))->toBe('Mantas');
    expect($request->param('doesnotexist', 'butthisdoes'))->toBe('butthisdoes');
});


test('Request::param failing', function () {
    $request = $this->request();

    expect($request->param('doesnotexist'))->toBe(null);
})->throws(OutOfBoundsException::class);


test('Request::params', function () {
    $this->set('GET', ['chuck' => 'schuldiner', 'born' => '1967']);
    $this->set('POST', ['first_band' => 'Mantas', 'born' => '1973']);
    $request = $this->request();

    // The order is important
    expect($request->params())->toBe([
        'first_band' => 'Mantas',
        'born' => '1967',
        'chuck' => 'schuldiner',
    ]);
});


test('Request::redirect temporary', function () {
    $thrown = false;

    try {
        $request = $this->request();
        $request->redirect('/login');
    } catch (ExitException) {
        $thrown = true;
    }

    expect($thrown)->toBe(true);
    expect(http_response_code())->toBe(302);
});


test('Request::redirect permanent', function () {
    $thrown = false;

    try {
        $request = $this->request();
        $request->redirect('/login', 301);
    } catch (ExitException) {
        $thrown = true;
    }

    expect($thrown)->toBe(true);
    expect(http_response_code())->toBe(301);
});


test('Request::addMethod', function () {
    $request = $this->request();
    $request->addMethod('founder', function (): string {
        return 'Chuck Schuldiner';
    });

    expect($request->founder())->toBe('Chuck Schuldiner');
});


test('Request::json', function () {
    // Simulates the php://input stream with a temp file
    ob_start();
    $request = $this->request();
    $f = tmpfile();
    $streamName = stream_get_meta_data($f)['uri'];
    fwrite($f, '[{"title": "Leprosy", "released": 1988}, {"title": "Human", "released": 1991}]');
    rewind($f);

    expect($request->json(stream: $streamName))->toBe([
        ["title" => "Leprosy", "released" => 1988],
        ["title" => "Human", "released" => 1991]
    ]);
    fclose($f);
    ob_end_clean();
});


test('Request::renderer', function () {
    $request = $this->request();
    $renderer = $request->renderer('json');

    expect($renderer)->toBeInstanceOf(JsonRenderer::class);
});


test('Request::renderer with args', function () {
    $config = $this->config();
    $config->addRenderer('template', TemplateRenderer::class, $this->templates());
    $request = $this->request(config: $config);
    $renderer = $request->renderer('template', 'renderer');

    expect($renderer)->toBeInstanceOf(TemplateRenderer::class);
});


test('Has file', function () {
    $this->setupFile();
    $request = $this->request();

    expect($request->hasFile('myfile'))->toBe(true);
});


test("Doesn't have file", function () {
    $this->setupFile();
    $request = $this->request();

    expect($request->hasFile('nofile'))->toBe(false);
});


test('Has multiple files', function () {
    $this->setupFile(); // Single file
    $request = $this->request();

    expect($request->hasFile('myfile'))->toBe(true);
    expect($request->hasFile('myfile') && $request->hasMultipleFiles('myfile'))->toBe(false);

    $this->setupFiles(); // Uploaded as HTML array
    $request = $this->request();

    expect($request->hasFile('myfile'))->toBe(true);
    expect($request->hasFile('myfile') && $request->hasMultipleFiles('myfile'))->toBe(true);
});


test("Get file instances", function () {
    $this->setupFile();
    $request = $this->request();
    $file = $request->file('myfile');

    expect($file)->toBeInstanceOf(File::class);
    expect($file->isValid())->toBe(true);

    $file = $request->file('failingfile');

    expect($file)->toBeInstanceOf(File::class);
    expect($file->isValid())->toBe(false);
});


test("Get files instances", function () {
    $this->setupFiles(); // files array
    $request = $this->request();
    $files = $request->files('myfile');

    expect(count($files))->toBe(2);
    expect($files[0])->toBeInstanceOf(File::class);
    expect($files[0]->isValid())->toBe(true);
    expect($files[1])->toBeInstanceOf(File::class);
    expect($files[1]->isValid())->toBe(false);
});


test("Get files instances with only one present", function () {
    $this->setupFile(); // single file
    $request = $this->request();
    $files = $request->files('myfile');

    expect(count($files))->toBe(1);
    expect($files[0])->toBeInstanceOf(File::class);
    expect($files[0]->isValid())->toBe(true);
});
