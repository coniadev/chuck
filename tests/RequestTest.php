<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Response;
use Chuck\Request;
use Chuck\Route;
use Chuck\Router;
use Chuck\ConfigInterface;
use Chuck\RouteInterface;
use Chuck\RouterInterface;
use Chuck\ResponseInterface;


uses(TestCase::class);


test('Helper methods', function () {
    $request = $this->request();

    expect($request->getConfig())->toBeInstanceOf(ConfigInterface::class);
    expect($request->getRouter())->toBeInstanceOf(RouterInterface::class);
    expect($request->getResponse())->toBeInstanceOf(ResponseInterface::class);
    expect($request->method())->toBe('GET');
    expect($request->isMethod('GET'))->toBe(true);
    expect($request->isMethod('POST'))->toBe(false);
});


test('Helper properties', function () {
    $request = $this->request(options: ['env' => 'chuckenv', 'debug' => true]);

    expect($request->config)->toBeInstanceOf(ConfigInterface::class);
    expect($request->router)->toBeInstanceOf(RouterInterface::class);
    expect($request->response)->toBeInstanceOf(ResponseInterface::class);
    expect($request->env)->toBe('chuckenv');
    expect($request->debug)->toBe(true);
});


test('Route property :: initialized', function () {
    $router = new Router();
    $router->addRoute(new Route('index', '/', fn (Request $request) => new Response($request, 200, 'Chuck')));
    $request = $this->request(method: 'GET', url: '/', router: $router);
    $router->dispatch($request);

    expect($request->route)->toBeInstanceOf(RouteInterface::class);
    expect($request->getRoute())->toBeInstanceOf(RouteInterface::class);
});


test('Route property :: uninitialized', function () {
    $request = $this->request();

    expect($request->route)->toBeInstanceOf(RouteInterface::class);
})->throws(\RuntimeException::class, 'Route is not initialized');


test('Route method :: uninitialized', function () {
    $request = $this->request();

    expect($request->getRoute())->toBeInstanceOf(RouteInterface::class);
})->throws(\RuntimeException::class, 'Route is not initialized');


test('Undefined property', function () {
    $request = $this->request();
    $request->doesnotexist;
})->throws(\RuntimeException::class, "Undefined request property 'doesnotexist'");


test('Url helpers', function () {
    $request = $this->request();

    expect($request->url())->toBe('/');
    expect($request->serverUrl())->toBe('http://www.example.com/');

    $this->setUrl('albums?from=1988&to=1991');
    expect($request->url())->toBe('/albums?from=1988&to=1991');
    expect($request->serverUrl())->toBe('http://www.example.com/albums?from=1988&to=1991');
    expect($request->urlPath())->toBe('/albums');
});


test('Generate route url', function () {
    $router = new Router();
    $albums = new Route('albums', 'albums/{from}/{to}', fn () => null);
    $router->addRoute($albums);
    $request = $this->request(router: $router);

    expect($request->routeUrl('albums', from: 1990, to: 1995))->toBe('http://www.example.com/albums/1990/1995');
    expect($request->routeUrl('albums', ['from' => 1988, 'to' => 1991]))->toBe('http://www.example.com/albums/1988/1991');
});


test('Static routes', function () {
    $ds = DIRECTORY_SEPARATOR;
    $router = new Router();
    $router->addStatic('static', '/static', __DIR__ . $ds . 'fixtures' . $ds . 'static');
    $request = $this->request(router: $router);

    expect($request->staticUrl('static', 'test.json'))->toBe('http://www.example.com/static/test.json');
    expect($request->staticUrl('static', 'test.json', true))->toMatch(
        '/http:\/\/www.example.com\/static\/test\.json\?v=[a-f0-9]{6}$/'
    );
    expect($request->staticUrl('static', 'test.json?exists=true', true))->toMatch(
        '/http:\/\/www.example.com\/static\/test\.json\?exists=true&v=[a-f0-9]{6}$/'
    );
});


test('Request::param', function () {
    $this->set('GET', ['chuck' => 'schuldiner', 'born' => '1967']);
    $this->set('POST', ['first_band' => 'Mantas']);
    $request = $this->request();

    expect($request->param('chuck'))->toBe('schuldiner');
    expect($request->param('born'))->toBe('1967');
    expect($request->param('first_band'))->toBe('Mantas');
    expect($request->param('doesnotexist'))->toBe(null);
    expect($request->param('doesnotexist', 'butthisdoes'))->toBe('butthisdoes');
});


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


test('Request::redirect', function () {
    $request = $this->request();
    $response = $request->redirect('/login');

    expect($response)->toBeInstanceOf(ResponseInterface::class);
    expect($response->getStatusCode())->toBe(302);

    $request = $this->request();
    $response = $request->redirect('/login', 301);

    expect($response->getStatusCode())->toBe(301);
});


test('Request::addMethod', function () {
    $request = $this->request();
    $request->addMethod('founder', function (): string {
        return 'Chuck Schuldiner';
    });

    expect($request->founder())->toBe('Chuck Schuldiner');
});


test('Request::response', function () {
    $request = $this->request();
    $response = $request->getResponse(
        404,
        'Pull the Plug',
        [['name' => 'Content-Type', 'value' => 'superior', 'replace' => false]],
        '1.2',
        'The Plug is Pulled',
    );


    expect($response->getStatusCode())->toBe(404);
    expect($response->getBody())->toBe('Pull the Plug');
    ob_start();
    $response->emit();
    ob_end_clean();
    expect($response->headersList())->toBe([
        'Content-Type: superior',
        'HTTP/1.2 404 The Plug is Pulled',
    ]);
});


test('Request::jsonBody', function () {
    // Simulates the php://input stream with a temp file
    $request = $this->request();
    $f = tmpfile();
    $streamName = stream_get_meta_data($f)['uri'];
    fwrite($f, '[{"title": "Leprosy", "released": 1988}, {"title": "Human", "released": 1991}]');
    rewind($f);

    expect($request->jsonBody(stream: $streamName))->toBe([
        ["title" => "Leprosy", "released" => 1988],
        ["title" => "Human", "released" => 1991]
    ]);
    fclose($f);
});