<?php

declare(strict_types=1);

use Conia\Chuck\Renderer\HtmlRenderer;
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\TextRenderer;
use Conia\Chuck\Tests\Setup\TestCase;

require __DIR__ . '/Setup/globalSymbols.php';

uses(TestCase::class);

test('JSON Renderer :: render()', function () {
    $renderer = new JsonRenderer($this->factory(), []);

    expect($renderer->render([
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ]))->toBe('{"album":"Spiritual Healing","released":1990}');
});


test('JSON Renderer :: render() iterator', function () {
    $renderer = new JsonRenderer($this->factory(), []);

    expect($renderer->render(_testJsonRendererIterator()))->toBe('[13,31,73]');
});


test('JSON Renderer :: render() with flags', function () {
    $renderer = new JsonRenderer($this->factory(), []);

    expect($renderer->render([
        'path' => 'album/leprosy',
    ]))->toBe('{"path":"album/leprosy"}');
    expect($renderer->render([
        'path' => 'album/leprosy',
    ], JSON_THROW_ON_ERROR))->toBe('{"path":"album\/leprosy"}');
});


test('JSON Renderer :: response()', function () {
    $renderer = new JsonRenderer($this->factory(), []);

    expect((string)$renderer->response([
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ])->getBody())->toBe('{"album":"Spiritual Healing","released":1990}');

    $renderer = new JsonRenderer($this->factory(), []);

    $response = $renderer->response(_testJsonRendererIterator());
    expect((string)$response->getBody())->toBe('[13,31,73]');

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value[0] === 'application/json') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
});


test('Html Renderer', function () {
    $renderer = new HtmlRenderer($this->factory(), []);
    $response = $renderer->response('<h1>Symbolic</h1>');

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value[0] === 'text/html') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect((string)$response->getBody())->toBe('<h1>Symbolic</h1>');
});


test('Text Renderer', function () {
    $renderer = new TextRenderer($this->factory(), []);
    $response = $renderer->response('Symbolic');

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value[0] === 'text/plain') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect((string)$response->getBody())->toBe('Symbolic');
});
