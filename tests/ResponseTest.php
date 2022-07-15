<?php

declare(strict_types=1);

use Conia\Chuck\Response\{Response, FileResponse};
use Conia\Chuck\Tests\Setup\{TestCase, C};
use Conia\Chuck\Error\HttpNotFound;

uses(TestCase::class);


test('Create with body', function () {
    $text = 'text';
    $response = new Response($text);
    expect($response->getBody())->toBe($text);
});


test('Init with header', function () {
    $response = new Response(headers: [['header-value', 'value', false]]);

    expect($response->headers->has('Header-Value'))->toBe(true);
});


test('Set header', function () {
    $response = new Response();
    $response->header('header-value', 'value', false);

    expect($response->headers->has('Header-Value'))->toBe(true);
});


test('HEAD request', function () {
    $request = $this->request(method: 'head');
    $response = $request->response->html('should not appear');

    expect((string)$response->getBody())->toBe('should not appear');
    ob_start();
    $response->emit();
    $content = ob_get_contents();
    ob_end_clean();
    expect(trim($content))->toBe('');
});


test('Request::response', function () {
    $request = $this->request();
    $response = $request->response->html('Pull the Plug');

    expect($response->getStatusCode())->toBe(200);
    expect((string)$response->getBody())->toBe('Pull the Plug');
});


test('Request::response::json', function () {
    $request = $this->request();
    $response = $request->response->json([1, 2, 3]);

    expect($response->getStatusCode())->toBe(200);
    expect((string)$response->getBody())->toBe('[1,2,3]');
});


test('Request::response::file', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $request = $this->request();
    $response = $request->response->file($file);

    expect($response)->toBeInstanceOf(FileResponse::class);
});


test('Response defaults', function () {
    $response = new Response('Pull the Plug');

    expect($response->getStatusCode())->toBe(200);
    expect((string)$response->getBody())->toBe('Pull the Plug');

    ob_start();
    $response->emit();
    ob_end_clean();

    expect($response->headers->emitted())->toBe([
        'Content-Type: text/html; charset=UTF-8',
        'HTTP/1.1 200 OK',
    ]);
});


test('Response overwrite defaults', function () {
    $response = (new Response(
        'Pull the Plug',
        headers: [['Content-Type', 'text/superior', false]]
    ))->protocol('1.2')->statusCode(404, 'The Plug is Pulled')->charset('UTF-32');

    expect($response->getStatusCode())->toBe(404);
    expect((string)$response->getBody())->toBe('Pull the Plug');

    ob_start();
    $response->emit();
    ob_end_clean();

    expect($response->headers()->emitted())->toBe([
        'Content-Type: text/superior; charset=UTF-32',
        'HTTP/1.2 404 The Plug is Pulled',
    ]);
});


test('File response', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response = new FileResponse($file);

    ob_start();
    $response->emit(cleanOutputBuffer: false);
    ob_end_clean();

    expect($response->headers()->emitted())->toContain('Content-Type: image/gif');
    expect($response->headers()->emitted())->toContain('Content-Length: 43');
    expect($response->headers()->emitted())->not->toContain(
        'Content-Disposition: attachment; filename="pixel.gif"'
    );
});


test('File response as download', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response = (new FileResponse($file))->download();

    ob_start();
    $response->emit(cleanOutputBuffer: false);
    ob_end_clean();

    expect($response->headers()->emitted())->toContain(
        'Content-Disposition: attachment; filename="pixel.gif"'
    );
});


test('File response with sendfile', function () {
    $_SERVER['SERVER_SOFTWARE'] = 'nginx';
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response = (new FileResponse($file))->download()->sendfile();

    ob_start();
    $response->emit(cleanOutputBuffer: false);
    ob_end_clean();
    expect($response->headers()->emitted())->toContain("X-Accel-Redirect: $file");


    $_SERVER['SERVER_SOFTWARE'] = 'apache';
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response = (new FileResponse($file))->download()->sendfile();

    ob_start();
    $response->emit(cleanOutputBuffer: false);
    ob_end_clean();
    expect($response->headers()->emitted())->toContain("X-Sendfile: $file");

    unset($_SERVER['SERVER_SOFTWARE']);
});


test('File response nonexistent file', function () {
    $file = C::root() . C::DS . 'static' . C::DS . 'pixel.jpg';
    new FileResponse($file);
})->throws(HttpNotFound::class);


test('File response nonexistent file with runtime error', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.jpg';
    new FileResponse($file, throwNotFound: false);
})->throws(RuntimeException::class, 'File not found');


test('File response body set', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    (new FileResponse($file))->body('');
})->throws(LogicException::class, 'The body cannot be set');
