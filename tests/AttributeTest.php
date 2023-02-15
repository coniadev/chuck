<?php

declare(strict_types=1);

use Conia\Chuck\Renderer\Render;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Tests\Fixtures\TestRenderer;
use Conia\Chuck\Tests\Fixtures\TestRendererArgsOptions;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);

test('Render json string', function () {
    $render = new Render('json');
    $result = $render->render($this->registry(), ['a' => 1, 'b' => 2]);

    expect($result)->toBe('{"a":1,"b":2}');
});

test('Render json response', function () {
    $render = new Render('json');
    $response = $render->response($this->registry(), ['a' => 1, 'b' => 2]);

    expect((string)$response->getBody())->toBe('{"a":1,"b":2}');
});

test('Render test renderer', function () {
    $registry = $this->registry();
    $registry->tag(Renderer::class)->add('test', TestRenderer::class);
    $render = new Render('test', contentType: 'application/xhtml+xml');
    $response = $render->response($registry, ['a' => 1, 'b' => 2]);

    expect($this->fullTrim((string)$response->getBody()))->toBe('Array( [a] => 1 [b] => 2)');
});

test('Render test renderer with args and options', function () {
    $registry = $this->registry();
    $registry
        ->tag(Renderer::class)
        ->add('test', TestRendererArgsOptions::class)
        ->args(option1: 13, option2: 'Option');
    $render = new Render('test', contentType: 'application/xhtml+xml');
    $response = $render->response($registry, ['a' => 1, 'b' => 2]);

    expect($this->fullTrim((string)$response->getBody()))
        ->toBe('{"a":1,"b":2,"contentType":"application/xhtml+xml","option1":13,"option2":"Option"}');
});

test('Render test renderer with options closure', function () {
    $registry = $this->registry();
    $registry
        ->tag(Renderer::class)
        ->add('test', TestRendererArgsOptions::class)
        ->args(fn () => ['option1' => 13, 'option2' => 'Option']);
    $render = new Render('test');
    $response = $render->response($registry, ['a' => 1, 'b' => 2]);

    expect($this->fullTrim((string)$response->getBody()))
        ->toBe('{"a":1,"b":2,"option1":13,"option2":"Option"}');
});
