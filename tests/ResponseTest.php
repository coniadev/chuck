<?php

declare(strict_types=1);

use Conia\Chuck\Response;
use Conia\Chuck\Tests\Setup\TestCase;

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
    $response->statusCode(404);

    expect($response->getStatusCode())->toBe(404);
    expect($response->getReasonPhrase())->toBe('Not Found');
});


test('Set status code and reason phrase', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response->statusCode(404, 'Nothing to see');

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
