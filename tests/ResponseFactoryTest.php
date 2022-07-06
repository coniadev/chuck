<?php

declare(strict_types=1);

use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Response\{Response, FileResponse, JsonResponse};
use Conia\Chuck\Tests\Setup\{C, TestCase};


uses(TestCase::class);


test('Html response', function () {
    $factory = new ResponseFactory();

    $response = $factory->html('html');
    expect($response->getBody())->toBe('html');
    expect($response)->toBeInstanceOf(Response::class);
});


test('Text response', function () {
    $factory = new ResponseFactory();

    $response = $factory->text('text');
    expect($response->getBody())->toBe('text');
    expect($response)->toBeInstanceOf(Response::class);
});


test('Json response', function () {
    $factory = new ResponseFactory();

    $response = $factory->json([1, 2, 3]);
    expect($response->getBody())->toBe('[1,2,3]');
    expect($response)->toBeInstanceOf(JsonResponse::class);
});


test('File response', function () {
    $file = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $factory = new ResponseFactory();

    $response = $factory->file($file);
    $response->download();
    expect($response)->toBeInstanceOf(FileResponse::class);
});
