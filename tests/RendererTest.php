<?php

declare(strict_types=1);

use Conia\Chuck\Exception\InvalidArgumentException;
use Conia\Chuck\Exception\ValueError;
use Conia\Chuck\Tests\Setup\{C, TestCase};
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\TextRenderer;

uses(TestCase::class);

test('JSON Renderer :: render()', function () {
    $renderer = new JsonRenderer($this->request(), []);

    expect($renderer->render([
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ]))->toBe('{"album":"Spiritual Healing","released":1990}');
});


test('JSON Renderer :: response()', function () {
    $renderer = new JsonRenderer($this->request(), []);

    expect((string)$renderer->response([
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ])->getBody())->toBe('{"album":"Spiritual Healing","released":1990}');

    // phpcs:disable
    function __json__renderer_iterator()
    {
        $arr = [13, 31, 73];
        foreach ($arr as $a) {
            yield $a;
        }
    }
    // phpcs:enable
    $renderer = new JsonRenderer($this->request(), []);

    $response = $renderer->response(__json__renderer_iterator());
    expect($response->getBody())->toBe('[13,31,73]');

    $hasContentType = false;
    foreach ($response->headers()->list() as $key => $value) {
        if ($key === 'Content-Type' && $value['value'][0] === 'application/json') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
});


test('String Renderer', function () {
    $renderer = new TextRenderer($this->request(), ['contentType' => 'text/html']);
    $response = $renderer->response('<h1>Symbolic</h1>');

    $hasContentType = false;
    foreach ($response->headers()->list() as $key => $value) {
        if ($key === 'Content-Type' && $value['value'][0] === 'text/html') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect($response->getBody())->toBe("<h1>Symbolic</h1>");
});


test('String Renderer :: wrong type', function () {
    (new TextRenderer($this->request(), []))->response([1, 2, 3]);
})->throws(ValueError::class, 'wrong type [array]');
