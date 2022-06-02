<?php

declare(strict_types=1);

use Chuck\Body\File;
use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Error\HttpNotFound;


uses(TestCase::class);


test('Request::response', function () {
    $request = $this->request();
    $response = $request->getResponse(
        404,
        'Pull the Plug',
        [['name' => 'Content-Type', 'value' => 'superior', 'replace' => false]],
        '1.2',
        'The Plug is Pulled',
    );

    expect($response->statusCode())->toBe(404);
    expect((string)$response->getBody())->toBe('Pull the Plug');
    ob_start();
    $response->emit();
    ob_end_clean();
    expect($response->getHeaderList())->toBe([
        'Content-Type: superior',
        'HTTP/1.2 404 The Plug is Pulled',
    ]);
});


test('File body', function () {
    $response = $this->request()->getResponse();
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
    $response = $this->request()->getResponse();
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
    $response = $this->request()->getResponse();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response->file($file, sendFile: true, asDownload: true);

    ob_start();
    $response->emit();
    ob_end_clean();
    expect($response->getHeaderList())->toContain("X-Accel-Redirect: $file");


    $_SERVER['SERVER_SOFTWARE'] = 'apache';
    $response = $this->request()->getResponse();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $response->file($file, sendFile: true, asDownload: true);

    ob_start();
    $response->emit();
    ob_end_clean();
    expect($response->getHeaderList())->toContain("X-Sendfile: $file");

    unset($_SERVER['SERVER_SOFTWARE']);
});


test('File body nonexistent file', function () {
    $response = $this->request()->getResponse();
    $file = C::root() . C::DS . 'static' . C::DS . 'pixel.jpg';
    $response->file($file);
})->throws(HttpNotFound::class);


test('File body nonexistent file with runtime error', function () {
    $response = $this->request()->getResponse();
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.jpg';
    $response->file($file, throwNotFound: false);
})->throws(RuntimeException::class, 'does not exist');
