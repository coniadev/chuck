<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\TextRenderer;

require __DIR__ . '/Setup/globalSymbols.php';

uses(TestCase::class);

test('JSON Renderer :: render()', function () {
    $renderer = new JsonRenderer($this->request(), $this->registry(), []);

    expect($renderer->render([
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ]))->toBe('{"album":"Spiritual Healing","released":1990}');
});


test('JSON Renderer :: response()', function () {
    $renderer = new JsonRenderer($this->request(), $this->registry(), []);

    expect((string)$renderer->response([
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ])->getBody())->toBe('{"album":"Spiritual Healing","released":1990}');

    $renderer = new JsonRenderer($this->request(), $this->registry(), []);

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


test('Text Renderer', function () {
    $renderer = new TextRenderer($this->request(), $this->registry(), []);
    $response = $renderer->response('<h1>Symbolic</h1>');

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value[0] === 'text/plain') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect((string)$response->getBody())->toBe("<h1>Symbolic</h1>");
});
