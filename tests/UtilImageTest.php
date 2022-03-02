<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Util\Image;


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


test('Failing static initialization', function () {
    Image::getImageFromPath($this->nonexistent);
})->throws(InvalidArgumentException::class, 'does not exist');


test('Static create resized', function () {
    $tmpfile = $this->cache . C::DS . 'temp.png';

    expect(file_exists($tmpfile))->toBe(false);

    $success = Image::createResizedImage($this->landscape, $tmpfile, 200);

    expect($success)->toBe(true);
    expect(file_exists($tmpfile))->toBe(true);

    unlink($tmpfile);
});
