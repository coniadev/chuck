<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{C, TestCase};
use Chuck\Renderer\JsonRenderer;
use Chuck\Renderer\TextRenderer;
use Chuck\Renderer\TemplateRenderer;

uses(TestCase::class);


test('JSON Renderer', function () {
    $renderer = new JsonRenderer($this->request(), [
        'album' => 'Spiritual Healing',
        'released' => 1990,
    ], []);

    expect((string)$renderer->response()->getBody())->toBe('{"album":"Spiritual Healing","released":1990}');

    function __json__renderer_iterator()
    {
        $arr = [13, 31, 73];
        foreach ($arr as $a) {
            yield $a;
        }
    }
    $renderer = new JsonRenderer($this->request(), __json__renderer_iterator(), []);

    $response = $renderer->response();
    expect($response->getBody())->toBe('[13,31,73]');

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value['value'][0] === 'application/json') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
});


test('String Renderer', function () {
    $renderer = new TextRenderer($this->request(), '<h1>Symbolic</h1>', ['contentType' => 'text/html']);
    $response = $renderer->response();

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value['value'][0] === 'text/html') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect($response->getBody())->toBe("<h1>Symbolic</h1>");
});


test('String Renderer :: wrong type', function () {
    (new TextRenderer($this->request(), [1, 2, 3], []))->response();
})->throws(ValueError::class, 'Wrong type [array]');


test('Template Renderer :: html (array of template dirs)', function () {
    $renderer = new TemplateRenderer(
        $this->request(),
        ['text' => 'numbers', 'arr' => [1, 2, 3]],
        ['renderer'],
        $this->templates(),
    );
    $response = $renderer->response();

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value['value'][0] === 'text/html') {
            $hasContentType = true;
        }
    }

    expect($hasContentType)->toBe(true);
    expect($response->getBody())->toBe("<h1>chuck</h1>\n<p>numbers</p><p>1</p><p>2</p><p>3</p>");
});


test('Template Renderer :: html (template dir as string)', function () {
    $renderer = new TemplateRenderer(
        $this->request(),
        ['text' => 'numbers', 'arr' => [1, 2, 3]],
        ['renderer'],
        C::root() . C::DS . 'templates' . C::DS . 'default',
    );
    $response = $renderer->response();

    expect($response->getBody())->toBe("<h1>chuck</h1>\n<p>numbers</p><p>1</p><p>2</p><p>3</p>");
});


test('Template Renderer :: xhtml', function () {
    $renderer = new TemplateRenderer(
        $this->request(),
        [],
        [
            'plain',
            'contentType' => 'application/xhtml+xml'
        ],
        $this->templates(),
    );
    $response = $renderer->response();

    $hasContentType = false;
    foreach ($response->headers() as $key => $value) {
        if ($key === 'Content-Type' && $value['value'][0] === 'application/xhtml+xml') {
            $hasContentType = true;
        }
    }
    expect($hasContentType)->toBe(true);
    expect($response->getBody())->toBe("<p>plain</p>\n");
});

test('Template Renderer :: iterator', function () {
    // Pass iterator
    $iter = function () {
        yield 'text' => 'characters';
        yield 'arr' => ['a', 'b', 'c'];
    };
    $renderer = new TemplateRenderer($this->request(), $iter(), ['renderer'], $this->templates());
    $response = $renderer->response();
    expect($response->getBody())->toBe("<h1>chuck</h1>\n<p>characters</p><p>a</p><p>b</p><p>c</p>");
});

test('Template Renderer :: template missing', function () {
    (new TemplateRenderer($this->request(), [], [], $this->templates()))->response();
})->throws(ValueError::class);

test('Template Renderer :: template dirs missing', function () {
    (new TemplateRenderer($this->request(), [], ['renderer'], []))->response();
})->throws(ValueError::class);
