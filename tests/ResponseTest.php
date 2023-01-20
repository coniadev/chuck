<?php

declare(strict_types=1);

use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Response;
use Conia\Chuck\Tests\Setup\C;
use Conia\Chuck\Tests\Setup\TestCase;
use Nyholm\Psr7\Stream;

uses(TestCase::class);


test('Get & set PSR-7 response', function () {
    $psr = $this->psrResponse();
    $response = new Response($psr);

    expect($response->psr())->toBe($psr);

    $response->setPsr($this->psrResponse());

    expect($response->psr())->not->toBe($psr);
});


test('Get status code', function () {
    $response = new Response($this->psrResponse());

    expect($response->getStatusCode())->toBe(200);
    expect($response->getReasonPhrase())->toBe('OK');
});


test('Set status code', function () {
    $response = new Response($this->psrResponse(), $this->factory());
    $response->status(404);

    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Not Found');
});


test('Set status code and reason phrase', function () {
    $response = new Response($this->psrResponse(), $this->factory());
    $response->status(404, 'Nothing to see');

    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Nothing to see');
});


test('Protocol version', function () {
    $response = new Response($this->psrResponse(), $this->factory());

    expect($response->getProtocolVersion())->toBe('1.1');

    $response->protocolVersion('2.0');

    expect($response->getProtocolVersion())->toBe('2.0');
});


test('Create with string body', function () {
    $text = 'text';
    $response = (new Response($this->psrResponse(), $this->factory()))->write($text);
    expect((string)$response->getBody())->toBe($text);
});


test('Set body', function () {
    $stream = $this->factory()->stream('Chuck text');
    $response = new Response($this->psrResponse());
    $response->body($stream);
    expect((string)$response->getBody())->toBe('Chuck text');
});


test('Fail setting body without factory', function () {
    $fh = fopen('php://temp', 'r+');
    fwrite($fh, 'Chuck resource');
    $response = new Response($this->psrResponse());
    $response->body('fails');
})->throws(RuntimeException::class, 'No factory');


test('Init with header', function () {
    $response = new Response($this->psrResponse());
    $response->header('header-value', 'value');

    expect($response->hasHeader('Header-Value'))->toBe(true);
});


test('Get header', function () {
    $response = new Response($this->psrResponse(), $this->factory());
    $response = $response->header('header-value', 'value');

    expect($response->getHeader('Header-Value')[0])->toBe('value');
});


test('Remove header', function () {
    $response = new Response($this->psrResponse(), $this->factory());
    $response->header('header-value', 'value');

    expect($response->hasHeader('Header-Value'))->toBe(true);

    $response = $response->removeHeader('header-value');

    expect($response->hasHeader('Header-Value'))->toBe(false);
});


test('Redirect temporary', function () {
    $response = new Response($this->psrResponse(), $this->factory());
    $response->redirect('/chuck');

    expect($response->getStatusCode())->toBe(302);
    expect($response->getHeader('Location')[0])->toBe('/chuck');
});


test('Redirect permanent', function () {
    $response = new Response($this->psrResponse(), $this->factory());
    $response->redirect('/chuck', 301);

    expect($response->getStatusCode())->toBe(301);
    expect($response->getHeader('Location')[0])->toBe('/chuck');
});


test('PSR-7 message wrapper methods', function () {
    $response = new Response($this->psrResponse(), $this->factory());
    $response->withProtocolVersion('2.0')
        ->withHeader('test-header', 'test-value')
        ->withHeader('test-header', 'test-value-replaced')
        ->withAddedHeader('test-header', 'test-value-added');

    $origBody = $response->getBody();
    $newBody = Stream::create('chuck');
    $response->withBody($newBody);

    expect((string)$origBody)->toBe('');
    expect((string)$newBody)->toBe('chuck');
    expect($response->getBody())->toBe($newBody);
    expect($response->getProtocolVersion())->toBe('2.0');
    expect(count($response->getHeaders()['test-header']))->toBe(2);
    expect($response->getHeaders()['test-header'][0])->toBe('test-value-replaced');
    expect($response->getHeaders()['test-header'][1])->toBe('test-value-added');
    expect($response->getHeader('test-header')[1])->toBe('test-value-added');
    expect($response->getHeaderLine('test-header'))->toBe('test-value-replaced, test-value-added');

    expect($response->hasHeader('test-header'))->toBe(true);
    $response->withoutHeader('test-header');
    expect($response->hasHeader('test-header'))->toBe(false);
});


test('Html response', function () {
    $response = Response::fromFactory($this->factory());
    $response = $response->html('<h1>Chuck string</h1>');

    expect((string)$response->getBody())->toBe('<h1>Chuck string</h1>');
    expect($response->getHeader('Content-Type')[0])->toBe('text/html');
});


test('Html response from resource', function () {
    $fh = fopen('php://temp', 'r+');
    fwrite($fh, '<h1>Chuck resource</h1>');
    $response = Response::fromFactory($this->factory())->html($fh);

    expect((string)$response->getBody())->toBe('<h1>Chuck resource</h1>');
    expect($response->getHeader('Content-Type')[0])->toBe('text/html');
});


test('Html response from Stringable', function () {
    $response = Response::fromFactory($this->factory())->html(new class () {
        public function __toString(): string
        {
            return '<h1>Chuck Stringable</h1>';
        }
    });

    expect((string)$response->getBody())->toBe('<h1>Chuck Stringable</h1>');
    expect($response->getHeader('Content-Type')[0])->toBe('text/html');
});


test('Html response invalid data', function () {
    Response::fromFactory($this->factory())->html(new stdClass());
})->throws(RuntimeException::class, 'strings, Stringable or resources');


test('Text response', function () {
    $response = Response::fromFactory($this->factory())->text('text');

    expect((string)$response->getBody())->toBe('text');
    expect($response->getHeader('Content-Type')[0])->toBe('text/plain');
});


test('Json response', function () {
    $response = Response::fromFactory($this->factory())->json([1, 2, 3]);

    expect((string)$response->getBody())->toBe('[1,2,3]');
    expect($response->getHeader('Content-Type')[0])->toBe('application/json');
});


test('Json response traversable', function () {
    $response = Response::fromFactory($this->factory())
        ->json(_testJsonRendererIterator());

    expect((string)$response->getBody())->toBe('[13,31,73]');
    expect($response->getHeader('Content-Type')[0])->toBe('application/json');
});


test('File response', function () {
    $file = C::root() . '/public/static/image.jpg';
    $response = Response::fromFactory($this->factory())->file($file);

    expect($response->getHeader('Content-Type')[0])->toBe('image/jpeg');
    expect($response->getHeader('Content-Length')[0])->toBe((string)filesize($file));
});


test('File download response', function () {
    $file = C::root() . '/public/static/image.jpg';
    $response = Response::fromFactory($this->factory())->download($file);

    expect($response->getHeader('Content-Type')[0])->toBe('image/jpeg');
    expect($response->getHeader('Content-Length')[0])->toBe((string)filesize($file));
    expect($response->getHeader('Content-Disposition')[0])->toBe(
        'attachment; filename="image.jpg"'
    );
});


test('File download response with changed name', function () {
    $file = C::root() . '/public/static/image.jpg';
    $response = Response::fromFactory($this->factory())->download($file, 'newname.jpg');

    expect($response->getHeader('Content-Type')[0])->toBe('image/jpeg');
    expect($response->getHeader('Content-Length')[0])->toBe((string)filesize($file));
    expect($response->getHeader('Content-Disposition')[0])->toBe(
        'attachment; filename="newname.jpg"'
    );
});


test('Sendfile response', function () {
    $_SERVER['SERVER_SOFTWARE'] = 'nginx';

    $file = C::root() . '/public/static/image.jpg';
    $response = Response::fromFactory($this->factory())->sendfile($file);

    expect($response->getHeader('X-Accel-Redirect')[0])->toBe($file);

    $_SERVER['SERVER_SOFTWARE'] = 'apache';

    $response = Response::fromFactory($this->factory())->sendfile($file);

    expect($response->getHeader('X-Sendfile')[0])->toBe($file);

    unset($_SERVER['SERVER_SOFTWARE']);
});

test('File response nonexistent file', function () {
    $file = C::root() . '/static/pixel.jpg';
    Response::fromFactory($this->factory())->file($file);
})->throws(HttpNotFound::class);


test('File response nonexistent file with runtime error', function () {
    $file = C::root() . '/public/static/pixel.jpg';
    Response::fromFactory($this->factory())->file($file, throwNotFound: false);
})->throws(RuntimeException::class, 'File not found');
