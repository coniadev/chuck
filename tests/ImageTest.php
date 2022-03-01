<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Image;


uses(TestCase::class);

beforeEach(function () {
    $this->landscape = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'landscape.png';
    $this->portrait = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'sub' . C::DS . 'portrait.png';
    $this->square = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'square.png';
});


test('Initialize', function () {
    $image = new Image($this->landscape);

    expect($image->get())->toBeInstanceOf(GdImage::class);
});


test('Missing width/height', function () {
    $image = new Image($this->landscape);
    $image->resize();
})->throws(\InvalidArgumentException::class, 'Height and/or width');


test('Resize width, place in bounding box', function () {
    $image = new Image($this->landscape);
    $gdImage = $image->resize(200);

    expect($gdImage)->toBeInstanceOf(GdImage::class);

    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(200);
    expect($h)->toBe(150);
});


test('Resize height, place in bounding box', function () {
    $image = new Image($this->landscape);
    $gdImage = $image->resize(height: 300);
    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(400);
    expect($h)->toBe(300);
});


test('Resize width/height, place in bounding box', function () {
    // Landscape mode
    $image = new Image($this->landscape);
    $gdImage = $image->resize(200, 200);
    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(200);
    expect($h)->toBe(150);

    // Portrait mode
    $image = new Image($this->portrait);
    $gdImage = $image->resize(200, 200);
    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(150);
    expect($h)->toBe(200);
});



test('Resize cropped', function () {
    $image = new Image($this->landscape);
    $gdImage = $image->resize(200, 200, true);
    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(200);
    expect($h)->toBe(200);

    $image = new Image($this->portrait);
    $gdImage = $image->resize(200, 200, true);
    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(200);
    expect($h)->toBe(200);

    $image = new Image($this->square);
    $gdImage = $image->resize(200, 200, true);
    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(200);
    expect($h)->toBe(200);
});
