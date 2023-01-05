<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\{TestCase, C};
use Conia\Chuck\Emitter;
use Conia\Chuck\ResponseFactory;

uses(TestCase::class);


test('SapiEmitter', function () {
    $factory = new ResponseFactory($this->registry());
    $response = $factory->json([1, 2, 3]);

    $emitter = new Emitter();
    ob_start();
    $emitter->emit($response->psr7());
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('[1,2,3]');
});


test('SapiStreamEmitter', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $factory = new ResponseFactory($this->registry());
    $response = $factory->download($file);

    $emitter = new Emitter();
    ob_start();
    $emitter->emit($response->psr7());
    $output = ob_get_contents();
    ob_end_clean();

    expect(str_starts_with($output, 'GIF87a'))->toBe(true);
});
