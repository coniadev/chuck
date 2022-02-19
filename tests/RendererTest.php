<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Renderer\JsonRenderer;
use Chuck\Renderer\StringRenderer;
use Chuck\Renderer\TemplateRenderer;

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


test('Template Renderer', function () {
    $renderer = new TemplateRenderer($this->request(), [
        'text' => 'numbers',
        'arr' => [1, 2, 3]
    ], ['default:renderer']);
    $hasContentType = false;
    foreach ($renderer->headers() as $header) {
        if ($header['name'] === 'Content-Type' && $header['value'] === 'text/html') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect($renderer->render())->toBe("<h1>chuck</h1>\n<p>numbers</p><p>1</p><p>2</p><p>3</p>");

    $renderer = new TemplateRenderer($this->request(), [], [
        'default:plain',
        'contentType' => 'application/xhtml+xml'
    ]);
    $hasContentType = false;
    foreach ($renderer->headers() as $header) {
        if ($header['name'] === 'Content-Type' && $header['value'] === 'application/xhtml+xml') {
            $hasContentType = true;
        }
    }
    expect($hasContentType)->toBe(true);
    expect($renderer->render())->toBe("<p>plain</p>\n");

    // Pass iterator
    $iter = function () {
        $arr = [1, 2, 3];
        foreach ($arr as $a) yield $a;
    };
    new TemplateRenderer($this->request(), $iter(), ['default:renderer']);
});
