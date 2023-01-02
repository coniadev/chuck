<?php

declare(strict_types=1);

use Conia\Chuck\Error\ValueError;
use Conia\Chuck\Tests\Setup\{C, TestCase};
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\TextRenderer;
use Conia\Chuck\Renderer\TemplateRenderer;

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


test('Template Renderer :: html (array of template dirs)', function () {
    $renderer = new TemplateRenderer(
        $this->request(),
        ['renderer'],
        $this->templates(),
    );
    $response = $renderer->response(['text' => 'numbers', 'arr' => [1, 2, 3]]);

    $hasContentType = false;
    foreach ($response->headers()->list() as $key => $value) {
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
        ['renderer'],
        C::root() . C::DS . 'templates' . C::DS . 'default',
    );
    $response = $renderer->response(['text' => 'numbers', 'arr' => [1, 2, 3]]);

    expect($response->getBody())->toBe("<h1>chuck</h1>\n<p>numbers</p><p>1</p><p>2</p><p>3</p>");
});


test('Template Renderer :: change content-type (named parameter)', function () {
    $renderer = new TemplateRenderer(
        $this->request(),
        [
            'plain',
            'contentType' => 'application/xhtml+xml'
        ],
        $this->templates(),
    );
    $response = $renderer->response([]);

    $hasContentType = false;
    foreach ($response->headers()->list() as $key => $value) {
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
    $renderer = new TemplateRenderer($this->request(), ['renderer'], $this->templates());
    $response = $renderer->response($iter());
    expect($response->getBody())->toBe("<h1>chuck</h1>\n<p>characters</p><p>a</p><p>b</p><p>c</p>");
});

test('Template Renderer :: template missing', function () {
    (new TemplateRenderer($this->request(), [], $this->templates()))->response([]);
})->throws(ValueError::class);

test('Template Renderer :: template dirs missing', function () {
    (new TemplateRenderer($this->request(), ['renderer'], []))->response([]);
})->throws(ValueError::class);

test('Template Renderer :: wrong context', function () {
    $renderer = new TemplateRenderer($this->request(), ['renderer'], $this->templates());
    $renderer->response(new stdClass());
})->throws(InvalidArgumentException::class);
