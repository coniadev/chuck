<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Image;


uses(TestCase::class);

beforeEach(function () {
    $this->path = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'large.png';
});


test('Initialize', function () {
    $image = new Image($this->path);

    expect($image->get())->toBeInstanceOf(GdImage::class);
});


test('Missing width/height', function () {
    $image = new Image($this->path);
    $image->resize();
})->throws(\InvalidArgumentException::class, 'Height and/or width');


test('Resize width', function () {
    $image = new Image($this->path);
    $gdImage = $image->resize(200);

    expect($gdImage)->toBeInstanceOf(GdImage::class);

    $x = imagesx($gdImage);
    $y = imagesy($gdImage);

    expect($x)->toBe(200);
    expect($y)->toBe(150);
});


test('Resize height', function () {
    $image = new Image($this->path);
    $gdImage = $image->resize(height: 300);

    expect($gdImage)->toBeInstanceOf(GdImage::class);

    $x = imagesx($gdImage);
    $y = imagesy($gdImage);

    expect($x)->toBe(400);
    expect($y)->toBe(300);
});
