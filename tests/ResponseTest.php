<?php

declare(strict_types=1);

use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Response;
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
