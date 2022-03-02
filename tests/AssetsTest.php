<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Assets\{Assets, Image};


uses(TestCase::class);


beforeEach(function () {
    $this->paths = [
        'path.assets' => 'public' . C::DS . 'assets',
        'path.cache' => 'public' . C::DS . 'cache',
    ];
    $this->landscape = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'landscape.png';
    $this->portrait = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'sub' . C::DS . 'portrait.png';
    $this->square = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'square.png';
});


test('Create instance from config', function () {
    $assets = Assets::fromConfig($this->config($this->paths));

    expect($assets)->toBeInstanceOf(Assets::class);
});


test('Resize to width', function () {
    $assets = Assets::fromConfig($this->config($this->paths));

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(200, 0, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect($assetImage)->toBeInstanceOf(Image::class);
    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-w200b.png'
    ))->toBe(true);
    expect(file_exists($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(file_exists($cacheImage->path()))->toBe(false);
});


test('Resize to height', function () {
    $assets = Assets::fromConfig($this->config($this->paths));

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(0, 200, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-h200b.png'
    ))->toBe(true);
    expect(file_exists($path))->toBe(true);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(file_exists($cacheImage->path()))->toBe(false);
});


test('Resize portrait to bounding box', function () {
    $assets = Assets::fromConfig($this->config($this->paths));

    $assetImage = $assets->image($this->portrait);
    $cacheImage = $assetImage->resize(200, 200, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'sub' . C::DS . 'portrait-200x200b.png'
    ))->toBe(true);
    expect(file_exists($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(150);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(file_exists($cacheImage->path()))->toBe(false);
});


test('Resize landscape to bounding box', function () {
    $assets = Assets::fromConfig($this->config($this->paths));

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(200, 200, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-200x200b.png'
    ))->toBe(true);
    expect(file_exists($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);
    expect(imagesy($image->get()))->toBe(150);

    $cacheImage->delete();

    expect(file_exists($cacheImage->path()))->toBe(false);
});


test('Crop landscape into bounding box', function () {
    $assets = Assets::fromConfig($this->config($this->paths));

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(200, 200, true);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-200x200c.png'
    ))->toBe(true);
    expect(file_exists($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(file_exists($cacheImage->path()))->toBe(false);
});


test('Crop portrait into bounding box', function () {
    $assets = Assets::fromConfig($this->config($this->paths));

    $assetImage = $assets->image($this->portrait);
    $cacheImage = $assetImage->resize(200, 200, true);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'sub' . C::DS . 'portrait-200x200c.png'

    ))->toBe(true);
    expect(file_exists($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(file_exists($cacheImage->path()))->toBe(false);
});


test('Resize one side 0',  function () {
    $assets = Assets::fromConfig($this->config($this->paths));
    $assetImage = $assets->image($this->landscape);
    $assetImage->resize(200, 0, true);
})->throws(InvalidArgumentException::class);
