<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Image;


uses(TestCase::class);

beforeEach(function () {
    $this->cache = C::root() . C::DS . 'public' . C::DS . 'cache';
    $this->landscape = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'landscape.png';
    $this->portrait = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'sub' . C::DS . 'portrait.png';
    $this->square = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'square.png';
    $this->jpeg = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.jpg';
    $this->webp = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.webp';
    $this->gif = C::root() . C::DS . 'public' . C::DS . 'static' . C::DS . 'pixel.gif';
    $this->nonexistent = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'doesnotexist.png';
    $this->wrongext = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'image.ext';
    $this->failing = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'failing.jpg';
});


test('Initialize PNG', function () {
    $tmpfile = $this->cache . C::DS . 'temp.png';
    $image = new Image($this->landscape);
    expect($image->get())->toBeInstanceOf(GdImage::class);
    $image->write($tmpfile);
    expect(file_exists($tmpfile))->toBe(true);
    unlink($tmpfile);
});


test('Initialize JPG', function () {
    $tmpfile = $this->cache . C::DS . 'temp.jpg';
    $image = new Image($this->jpeg);
    expect($image->get())->toBeInstanceOf(GdImage::class);
    $image->write($tmpfile);
    expect(file_exists($tmpfile))->toBe(true);
    unlink($tmpfile);
});


test('Initialize WEBP', function () {
    $tmpfile = $this->cache . C::DS . 'temp.webp';
    $image = new Image($this->webp);
    expect($image->get())->toBeInstanceOf(GdImage::class);
    $image->write($tmpfile);
    expect(file_exists($tmpfile))->toBe(true);
    unlink($tmpfile);
});


test('Initialize GIF', function () {
    $tmpfile = $this->cache . C::DS . 'temp.gif';
    $image = new Image($this->gif);
    expect($image->get())->toBeInstanceOf(GdImage::class);
    $image->write($tmpfile);
    expect(file_exists($tmpfile))->toBe(true);
    unlink($tmpfile);
});


test('Failing initialization', function () {
    $image = new Image($this->nonexistent);
    $image->get();
})->throws(RuntimeException::class, 'does not exist');


test('Failing write', function () {
    $image = new Image($this->landscape);
    $image->write($this->cache . C::DS . 'temp.ext');
})->throws(InvalidArgumentException::class, 'extension not supported');


test('Failing file extension', function () {
    $image = new Image($this->wrongext);
    $image->get();
})->throws(InvalidArgumentException::class, 'is not a valid');


test('Failing image', function () {
    $image = new Image($this->failing);
    $image->get();
})->throws(InvalidArgumentException::class, 'is not a valid');


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


test('Already in bounding box', function () {
    $image = new Image($this->landscape);
    $gdImage = $image->resize(1000, 1000);
    $w = imagesx($gdImage);
    $h = imagesy($gdImage);

    expect($w)->toBe(800);
    expect($h)->toBe(600);
});
