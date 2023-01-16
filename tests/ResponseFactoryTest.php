<?php

declare(strict_types=1);

use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Tests\Setup\C;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Empty response', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->create(404, 'Nothing to see');

    expect((string)$response->getBody())->toBe('');
    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Nothing to see');
});


test('Html response', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->html('<h1>Chuck string</h1>');

    expect((string)$response->getBody())->toBe('<h1>Chuck string</h1>');
    expect($response->getHeader('Content-Type')[0])->toBe('text/html');
});


test('Html response from resource', function () {
    $fh = fopen('php://temp', 'r+');
    fwrite($fh, '<h1>Chuck resource</h1>');
    $factory = new ResponseFactory($this->registry());
    $response = $factory->html($fh);

    expect((string)$response->getBody())->toBe('<h1>Chuck resource</h1>');
    expect($response->getHeader('Content-Type')[0])->toBe('text/html');
});


test('Html response from Stringable', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->html(new class () {
        public function __toString(): string
        {
            return '<h1>Chuck Stringable</h1>';
        }
    });

    expect((string)$response->getBody())->toBe('<h1>Chuck Stringable</h1>');
    expect($response->getHeader('Content-Type')[0])->toBe('text/html');
});


test('Html response invalid data', function () {
    $factory = new ResponseFactory($this->registry());
    $factory->html(new stdClass());
})->throws(RuntimeException::class, 'strings, Stringable or resources');


test('Text response', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->text('text');

    expect((string)$response->getBody())->toBe('text');
    expect($response->getHeader('Content-Type')[0])->toBe('text/plain');
});


test('Json response', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->json([1, 2, 3]);

    expect((string)$response->getBody())->toBe('[1,2,3]');
    expect($response->getHeader('Content-Type')[0])->toBe('application/json');
});


test('Json response traversable', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->json(_testJsonRendererIterator());

    expect((string)$response->getBody())->toBe('[13,31,73]');
    expect($response->getHeader('Content-Type')[0])->toBe('application/json');
});


test('File response', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $factory = new ResponseFactory($this->registry());
    $response = $factory->file($file);

    expect($response->getHeader('Content-Type')[0])->toBe('image/jpeg');
    expect($response->getHeader('Content-Length')[0])->toBe((string)filesize($file));
});


test('File download response', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $factory = new ResponseFactory($this->registry());
    $response = $factory->download($file);

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
