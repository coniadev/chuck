<?php

declare(strict_types=1);

use Conia\Chuck\Response;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Get status code', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());

    expect($response->getStatusCode())->toBe(200);
});


test('Create with body', function () {
    $text = 'text';
    $response = (new Response($this->psr7Response(), $this->psr7Factory()))->body($text);
    expect((string)$response->getBody())->toBe($text);
});


test('Init with header', function () {
    $response = new Response($this->psr7Response(), $this->psr7Factory());
    $response = $response->header('header-value', 'value');

    expect($response->hasHeader('Header-Value'))->toBe(true);
});
