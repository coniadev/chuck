<?php

declare(strict_types=1);

use Conia\Chuck\Attribute\Render;
use Conia\Chuck\Renderer\TemplateRenderer;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Render json', function () {
    $render = new Render('json');
    $response = $render->response($this->request(), ['a' => 1, 'b' => 2]);

    expect($response->getBody())->toBe('{"a":1,"b":2}');
});


test('Render template', function () {
    $config = $this->config();
    $config->addRenderer('template', TemplateRenderer::class, $this->templates());
    $render = new Render('template', 'plain', contentType: 'application/xhtml+xml');
    $response = $render->response($this->request(config: $config), ['a' => 1, 'b' => 2]);

    expect($this->fullTrim($response->getBody()))->toBe('<p>plain</p>');
});
