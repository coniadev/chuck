<?php

declare(strict_types=1);

use Conia\Chuck\Http\Emitter;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Tests\Setup\C;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('SapiEmitter', function () {
    $factory = new ResponseFactory($this->factory());
    $response = $factory->json([1, 2, 3]);

    $emitter = new Emitter();
    ob_start();
    $emitter->emit($response->psr());
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('[1,2,3]');
});


test('SapiStreamEmitter', function () {
    $file = C::root() . '/public/static/pixel.gif';
    $factory = new ResponseFactory($this->factory());
    $response = $factory->download($file);

    $emitter = new Emitter();
    ob_start();
    $emitter->emit($response->psr());
    $output = ob_get_contents();
    ob_end_clean();

    expect(str_starts_with($output, 'GIF87a'))->toBe(true);
});
