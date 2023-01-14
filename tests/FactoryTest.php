<?php

declare(strict_types=1);

use Conia\Chuck\Http\Guzzle;
use Conia\Chuck\Http\Nyholm;
use Conia\Chuck\Tests\Setup\TestCase;

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
