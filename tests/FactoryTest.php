<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\Http\Factory;
use Conia\Chuck\Http\Guzzle;
use Conia\Chuck\Http\Laminas;
use Conia\Chuck\Http\Nyholm;
use Conia\Chuck\Tests\Setup\TestCase;
use Psr\Http\Message\ServerRequestInterface;

uses(TestCase::class);


test('Nyholm', function () {
    $factory = new Nyholm();

    $request = $factory->request();
    expect($request)->toBeInstanceOf(\Nyholm\Psr7\ServerRequest::class);

    $response = $factory->response();
    expect($response)->toBeInstanceOf(\Nyholm\Psr7\Response::class);

    $stream = $factory->stream();
    expect($stream)->toBeInstanceOf(\Nyholm\Psr7\Stream::class);

    $stream = $factory->stream(fopen('php://temp', 'r+'));
    expect($stream)->toBeInstanceOf(\Nyholm\Psr7\Stream::class);

    $stream = $factory->streamFromFile(__DIR__ . '/Fixtures/public/assets/image.webp');
    expect($stream)->toBeInstanceOf(\Nyholm\Psr7\Stream::class);
});


test('Nyholm stream failing', function () {
    (new Nyholm())->stream(new stdClass());
})->throws(RuntimeException::class, 'Only strings');


test('Nyholm app run', function () {
    $app = App::create();
    $app->register(Factory::class, Nyholm::class);
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    $registry = $app->registry();
    ob_start();
    $response = $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
    expect($response->psr7())->toBeInstanceOf(\Nyholm\Psr7\Response::class);

    $request1 = $registry->get(ServerRequestInterface::class);
    expect($request1)->toBeInstanceOf(ServerRequestInterface::class);

    $request2 = $registry->get(\Nyholm\Psr7\ServerRequest::class);
    expect($request2)->toBeInstanceOf(\Nyholm\Psr7\ServerRequest::class);
    expect($request1)->toBe($request2);
});


test('Guzzle', function () {
    $factory = new Guzzle();

    $request = $factory->request();
    expect($request)->toBeInstanceOf(\GuzzleHttp\Psr7\ServerRequest::class);

    $response = $factory->response();
    expect($response)->toBeInstanceOf(\GuzzleHttp\Psr7\Response::class);

    $stream = $factory->stream();
    expect($stream)->toBeInstanceOf(\GuzzleHttp\Psr7\Stream::class);

    $stream = $factory->stream(fopen('php://temp', 'r+'));
    expect($stream)->toBeInstanceOf(\GuzzleHttp\Psr7\Stream::class);

    $stream = $factory->streamFromFile(__DIR__ . '/Fixtures/public/assets/image.webp');
    expect($stream)->toBeInstanceOf(\GuzzleHttp\Psr7\Stream::class);
});


test('Guzzle stream failing', function () {
    (new Guzzle())->stream(new stdClass());
})->throws(RuntimeException::class, 'Only strings');


test('Guzzle app run', function () {
    $app = App::create();
    $app->register(Factory::class, Guzzle::class);
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    $registry = $app->registry();
    ob_start();
    $response = $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
    expect($response->psr7())->toBeInstanceOf(\GuzzleHttp\Psr7\Response::class);

    $request1 = $registry->get(ServerRequestInterface::class);
    expect($request1)->toBeInstanceOf(ServerRequestInterface::class);

    $request2 = $registry->get(\GuzzleHttp\Psr7\ServerRequest::class);
    expect($request2)->toBeInstanceOf(\GuzzleHttp\Psr7\ServerRequest::class);
    expect($request1)->toBe($request2);
});


test('Laminas', function () {
    $factory = new Laminas();

    $request = $factory->request();
    expect($request)->toBeInstanceOf(\Laminas\Diactoros\ServerRequest::class);

    $response = $factory->response();
    expect($response)->toBeInstanceOf(\Laminas\Diactoros\Response::class);

    $stream = $factory->stream();
    expect($stream)->toBeInstanceOf(\Laminas\Diactoros\Stream::class);

    $stream = $factory->stream(fopen('php://temp', 'r+'));
    expect($stream)->toBeInstanceOf(\Laminas\Diactoros\Stream::class);

    $stream = $factory->streamFromFile(__DIR__ . '/Fixtures/public/assets/image.webp');
    expect($stream)->toBeInstanceOf(\Laminas\Diactoros\Stream::class);
});


test('Laminas stream failing', function () {
    (new Laminas())->stream(new stdClass());
})->throws(RuntimeException::class, 'Only strings');


test('Laminas app run', function () {
    $app = App::create();
    $app->register(Factory::class, Laminas::class);
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    $registry = $app->registry();
    ob_start();
    $response = $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('text');
    expect($response->psr7())->toBeInstanceOf(\Laminas\Diactoros\Response::class);

    $request1 = $registry->get(ServerRequestInterface::class);
    expect($request1)->toBeInstanceOf(ServerRequestInterface::class);

    $request2 = $registry->get(\Laminas\Diactoros\ServerRequest::class);
    expect($request2)->toBeInstanceOf(\Laminas\Diactoros\ServerRequest::class);
    expect($request1)->toBe($request2);
});
