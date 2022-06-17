<?php

declare(strict_types=1);

use Chuck\Response\{Response, FileResponse};
use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Error\HttpNotFound;


uses(TestCase::class);


test('Create with body', function () {
    $text = 'text';
    $response = new Response($text);
    expect($response->getBody())->toBe($text);
});


test('Set header', function () {
    $response = new Response(headers: [['name' => 'header-value', 'value' => 'value', 'replace' => false]]);

    expect(array_key_exists('Header-Value', $response->headers()))->toBe(true);
});


test('Set header replace false', function () {
    $response = new Response();
    $response->header('header-value', 'value', false);
    $response->header('header-value', 'value2', false);

    $headers = $response->headers();

    expect(array_key_exists('Header-Value', $headers))->toBe(true);
    expect(count($headers['Header-Value']['value']))->toBe(2);
});


test('Set invalid header', function () {
    new Response(headers: [['name' => 'wrong header', 'value' => 'value']]);
})->throws(ValueError::class);


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

    expect($response->getWrittenHeaderList())->toBe([
        'Content-Type: text/html; charset=UTF-8',
        'HTTP/1.1 200 OK',
    ]);
});


test('Response overwrite defaults', function () {
    $response = (new Response(
        'Pull the Plug',
        headers: [['name' => 'Content-Type', 'value' => 'text/superior', 'replace' => false]]
    ))->protocol('1.2')->statusCode(404, 'The Plug is Pulled')->charset('UTF-32');

    expect($response->getStatusCode())->toBe(404);
    expect((string)$response->getBody())->toBe('Pull the Plug');

    ob_start();
    $response->emit();
    ob_end_clean();

    expect($response->getWrittenHeaderList())->toBe([
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

    expect($response->getWrittenHeaderList())->toContain('Content-Type: image/gif');
    expect($response->getWrittenHeaderList())->toContain('Content-Length: 43');
    expect($response->getWrittenHeaderList())->not->toContain(
        'Content-Disposition: attachment; filename="pixel.gif"'
    );
});


test('File response as download', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response = (new FileResponse($file))->download();

    ob_start();
    $response->emit(cleanOutputBuffer: false);
    ob_end_clean();

    expect($response->getWrittenHeaderList())->toContain(
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
    expect($response->getWrittenHeaderList())->toContain("X-Accel-Redirect: $file");


    $_SERVER['SERVER_SOFTWARE'] = 'apache';
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response = (new FileResponse($file))->download()->sendfile();

    ob_start();
    $response->emit(cleanOutputBuffer: false);
    ob_end_clean();
    expect($response->getWrittenHeaderList())->toContain("X-Sendfile: $file");

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
