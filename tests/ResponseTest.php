<?php

declare(strict_types=1);

use Conia\Chuck\Response;
use Conia\Chuck\Tests\Setup\TestCase;
use Nyholm\Psr7\Stream;

uses(TestCase::class);


test('Get & set PSR-7 response', function () {
    $psr7 = $this->psr7Response();
    $response = new Response($psr7, $this->psr7Factory());

    expect($response->psr7())->toBe($psr7);

    $response->setPsr7($this->psr7Response());

    expect($response->psr7())->not->toBe($psr7);
});


test('Get status code', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());

    expect($response->getStatusCode())->toBe(200);
    expect($response->getReasonPhrase())->toBe('OK');
});


test('Set status code', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->status(404);

    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Not Found');
});


test('Set status code and reason phrase', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->status(404, 'Nothing to see');

    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Nothing to see');
});


test('Set status code with PSR-7 Wrapper', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->withStatus(404);

    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Not Found');
});


test('Set status code and reason phrase with PSR-7 Wrapper', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->withStatus(404, 'Nothing to see');

    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Nothing to see');
});


test('Protocol version', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());

    expect($response->getProtocolVersion())->toBe('1.1');

    $response->protocolVersion('2.0');

    expect($response->getProtocolVersion())->toBe('2.0');
});


test('Create with body', function () {
    $text = 'text';
    $response = (new Response($this->psr7Response(), $this->psr7Factory()))->body($text);
    expect((string)$response->getBody())->toBe($text);
});


test('Init with header', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->header('header-value', 'value');

    expect($response->hasHeader('Header-Value'))->toBe(true);
});


test('Get header', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response = $response->header('header-value', 'value');

    expect($response->getHeader('Header-Value')[0])->toBe('value');
});


test('Remove header', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->header('header-value', 'value');

    expect($response->hasHeader('Header-Value'))->toBe(true);

    $response = $response->removeHeader('header-value');

    expect($response->hasHeader('Header-Value'))->toBe(false);
});


test('Redirect temporary', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->redirect('/chuck');

    expect($response->getStatusCode())->toBe(302);
    expect($response->getHeader('Location')[0])->toBe('/chuck');
});


test('Redirect permanent', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->redirect('/chuck', 301);

    expect($response->getStatusCode())->toBe(301);
    expect($response->getHeader('Location')[0])->toBe('/chuck');
});


test('PSR-7 message wrapper methods', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
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
