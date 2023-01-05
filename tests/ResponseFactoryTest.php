<?php

declare(strict_types=1);

use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Response;
use Conia\Chuck\Tests\Setup\{C, TestCase};

uses(TestCase::class);


test('Html response', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->html('html');

    expect((string)$response->getBody())->toBe('html');
    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getHeader('Content-Type')[0])->toBe('text/html');
});


test('Text response', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->text('text');

    expect((string)$response->getBody())->toBe('text');
    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getHeader('Content-Type')[0])->toBe('text/plain');
});


test('Json response', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->json([1, 2, 3]);

    expect((string)$response->getBody())->toBe('[1,2,3]');
    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getHeader('Content-Type')[0])->toBe('application/json');
});


test('File response', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $factory = new ResponseFactory($this->registry());
    $response = $factory->file($file);

    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getHeader('Content-Type')[0])->toBe('image/jpeg');
    expect($response->getHeader('Content-Length')[0])->toBe((string)filesize($file));
});


test('File download response', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $factory = new ResponseFactory($this->registry());
    $response = $factory->download($file);

    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getHeader('Content-Type')[0])->toBe('image/jpeg');
    expect($response->getHeader('Content-Length')[0])->toBe((string)filesize($file));
    expect($response->getHeader('Content-Disposition')[0])->toBe(
        'attachment; filename="image.jpg"'
    );
});


test('File download response with changed name', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $factory = new ResponseFactory($this->registry());
    $response = $factory->download($file, 'newname.jpg');

    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getHeader('Content-Type')[0])->toBe('image/jpeg');
    expect($response->getHeader('Content-Length')[0])->toBe((string)filesize($file));
    expect($response->getHeader('Content-Disposition')[0])->toBe(
        'attachment; filename="newname.jpg"'
    );
});


test('Sendfile response', function () {
    $_SERVER['SERVER_SOFTWARE'] = 'nginx';

    $file = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $response = (new ResponseFactory($this->registry()))->sendfile($file);

    expect($response->getHeader('X-Accel-Redirect')[0])->toBe($file);

    $_SERVER['SERVER_SOFTWARE'] = 'apache';

    $response = (new ResponseFactory($this->registry()))->sendfile($file);

    expect($response->getHeader('X-Sendfile')[0])->toBe($file);

    unset($_SERVER['SERVER_SOFTWARE']);
});

test('File response nonexistent file', function () {
    $file = C::root() . C::DS . 'static' . C::DS . 'pixel.jpg';
    (new ResponseFactory($this->registry()))->file($file);
})->throws(HttpNotFound::class);


test('File response nonexistent file with runtime error', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.jpg';
    (new ResponseFactory($this->registry()))->file($file, throwNotFound: false);
})->throws(RuntimeException::class, 'File not found');
