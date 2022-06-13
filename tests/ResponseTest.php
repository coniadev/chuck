<?php

declare(strict_types=1);

use Chuck\Response;
use Chuck\Body\{File, Text};
use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Error\HttpNotFound;


uses(TestCase::class);


test('Create with body', function () {
    $text = new Text('text');
    $response = new Response(body: $text);
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
    $response = $request->response(body: new Text('should not appear'));

    expect((string)$response->getBody())->toBe('should not appear');
    ob_start();
    $response->emit();
    $content = ob_get_contents();
    ob_end_clean();
    expect(trim($content))->toBe('');
});


test('Request::response', function () {
    $request = $this->request();
    $response = $request->response(
        404,
        'Pull the Plug',
        [['name' => 'Content-Type', 'value' => 'text/superior', 'replace' => false]],
        '1.2',
        'The Plug is Pulled',
    );

    expect($response->statusCode())->toBe(404);
    expect((string)$response->getBody())->toBe('Pull the Plug');
    ob_start();
    $response->emit();
    ob_end_clean();
    expect($response->getHeaderList())->toBe([
        'Content-Type: text/superior; charset=UTF-8',
        'HTTP/1.2 404 The Plug is Pulled',
    ]);
});


test('File body', function () {
    $response = $this->request()->response();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response->file($file);

    expect($response->getBody())->toBeInstanceOf(File::class);

    ob_start();
    $response->emit();
    ob_end_clean();

    expect($response->getHeaderList())->toContain('Content-Type: image/gif');
    expect($response->getHeaderList())->toContain('Content-Length: 43');
    expect($response->getHeaderList())->not->toContain(
        'Content-Disposition: attachment; filename="pixel.gif"'
    );
});


test('File body as download', function () {
    $response = $this->request()->response();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response->file($file, asDownload: true);

    ob_start();
    $response->emit();
    ob_end_clean();

    expect($response->getHeaderList())->toContain(
        'Content-Disposition: attachment; filename="pixel.gif"'
    );
});


test('File body with sendfile', function () {
    $_SERVER['SERVER_SOFTWARE'] = 'nginx';
    $response = $this->request()->response();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response->file($file, sendFile: true, asDownload: true);

    ob_start();
    $response->emit();
    ob_end_clean();
    expect($response->getHeaderList())->toContain("X-Accel-Redirect: $file");


    $_SERVER['SERVER_SOFTWARE'] = 'apache';
    $response = $this->request()->response();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response->file($file, sendFile: true, asDownload: true);

    ob_start();
    $response->emit();
    ob_end_clean();
    expect($response->getHeaderList())->toContain("X-Sendfile: $file");

    unset($_SERVER['SERVER_SOFTWARE']);
});


test('File body nonexistent file', function () {
    $response = $this->request()->response();
    $file = C::root() . C::DS . 'static' . C::DS . 'pixel.jpg';
    $response->file($file);
})->throws(HttpNotFound::class);


test('File body nonexistent file with runtime error', function () {
    $response = $this->request()->response();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.jpg';
    $response->file($file, throwNotFound: false);
})->throws(RuntimeException::class, 'does not exist');
