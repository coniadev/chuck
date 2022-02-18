<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Renderer\JsonRenderer;
use Chuck\Renderer\StringRenderer;

uses(TestCase::class);


test('JSON Renderer', function () {
    $renderer = new JsonRenderer($this->request(), [
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ], []);

    expect($renderer->render())->toBe('{"album":"Spiritual Healing","released":1990}');

    function __json__renderer_iterator()
    {
        $arr = [13, 31, 73];
        foreach ($arr as $a) {
            yield $a;
        }
    }
    $renderer = new JsonRenderer($this->request(), __json__renderer_iterator(), []);

    expect($renderer->render())->toBe('[13,31,73]');

    $hasContentType = false;
    foreach ($renderer->headers() as $header) {
        if ($header['name'] === 'Content-Type' && $header['value'] === 'application/json') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
});


test('String Renderer', function () {
    $renderer = new StringRenderer($this->request(), [1, 2, 3], []);
    $hasContentType = false;
    foreach ($renderer->headers() as $header) {
        if ($header['name'] === 'Content-Type' && $header['value'] === 'text/plain') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect($renderer->render())->toBe("Array\n(\n    [0] => 1\n    [1] => 2\n    [2] => 3\n)\n");

    $renderer = new StringRenderer($this->request(), '<h1>Symbolic</h1>', ['contentType' => 'text/html']);
    $hasContentType = false;
    foreach ($renderer->headers() as $header) {
        if ($header['name'] === 'Content-Type' && $header['value'] === 'text/html') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect($renderer->render())->toBe("<h1>Symbolic</h1>");
});
