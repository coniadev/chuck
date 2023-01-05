<?php

declare(strict_types=1);

use Conia\Chuck\Attribute\Render;
use Conia\Chuck\Tests\Fixtures\TestRenderer;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Render json', function () {
    $render = new Render('json');
    $response = $render->response($this->request(), $this->config(), $this->registry(), ['a' => 1, 'b' => 2]);

    expect((string)$response->getBody())->toBe('{"a":1,"b":2}');
});


test('Render test renderer', function () {
    $config = $this->config();
    $config->addRenderer('template', TestRenderer::class);
    $render = new Render('template', contentType: 'application/xhtml+xml');
    $response = $render->response($this->request(), $config, $this->registry(), ['a' => 1, 'b' => 2]);

    expect($this->fullTrim((string)$response->getBody()))->toBe('Array( [a] => 1 [b] => 2)');
});
