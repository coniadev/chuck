<?php

declare(strict_types=1);

use Chuck\Routing\Router;
use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Assets\{Assets, Image};


uses(TestCase::class);


beforeEach(function () {
    $this->paths = [
        'assets' => C::root() . C::DS . 'public' . C::DS . 'assets',
        'cache' => C::root() . C::DS . 'public' . C::DS . 'cache' . C::DS . 'assets',
    ];
    $this->landscape = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'landscape.png';
    $this->portrait = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'sub' . C::DS . 'portrait.png';
    $this->square = C::root() . C::DS . 'public' . C::DS . 'assets' . C::DS . 'square.png';
});


test('Create instance from config', function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);

    expect($assets)->toBeInstanceOf(Assets::class);
});


test('Resize to width', function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(200, 0, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect($assetImage)->toBeInstanceOf(Image::class);
    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-w200b.png'
    ))->toBe(true);
    expect(is_file($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(is_file($cacheImage->path()))->toBe(false);
});


test('Resize to height', function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(0, 200, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-h200b.png'
    ))->toBe(true);
    expect(is_file($path))->toBe(true);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(is_file($cacheImage->path()))->toBe(false);
});


test('Resize portrait to bounding box', function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);

    $assetImage = $assets->image($this->portrait);
    $cacheImage = $assetImage->resize(200, 200, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'sub' . C::DS . 'portrait-200x200b.png'
    ))->toBe(true);
    expect(is_file($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(150);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(is_file($cacheImage->path()))->toBe(false);
});


test('Resize landscape to bounding box', function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(200, 200, false);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-200x200b.png'
    ))->toBe(true);
    expect(is_file($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);
    expect(imagesy($image->get()))->toBe(150);

    $cacheImage->delete();

    expect(is_file($cacheImage->path()))->toBe(false);
});


test('Crop landscape into bounding box', function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);

    $assetImage = $assets->image($this->landscape);
    $cacheImage = $assetImage->resize(200, 200, true);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'landscape-200x200c.png'
    ))->toBe(true);
    expect(is_file($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(is_file($cacheImage->path()))->toBe(false);
});


test('Crop portrait into bounding box', function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);

    $assetImage = $assets->image($this->portrait);
    $cacheImage = $assetImage->resize(200, 200, true);
    $path = $cacheImage->path();
    $image = $cacheImage->get();

    expect(str_ends_with(
        $path,
        'assets' . C::DS . 'sub' . C::DS . 'portrait-200x200c.png'

    ))->toBe(true);
    expect(is_file($path))->toBe(true);
    expect(imagesx($image->get()))->toBe(200);
    expect(imagesy($image->get()))->toBe(200);

    $cacheImage->delete();

    expect(is_file($cacheImage->path()))->toBe(false);
});


test('Resize one side 0',  function () {
    $assets = new Assets($this->paths['assets'], $this->paths['cache']);
    $assetImage = $assets->image($this->landscape);
    $assetImage->resize(200, 0, true);
})->throws(ValueError::class);


test('Static route', function () {
    $router = new Router();
    $router->addStatic('assets', '/assets', C::root() . C::DS . 'public' . C::DS . 'assets');
    $assets = new Assets(
        $this->paths['assets'],
        $this->paths['cache'],
        $this->request(router: $router)
    );
    $image = $assets->image($this->portrait);

    expect(is_file($image->path()))->toBe(true);
    expect($image->url())->toMatch('/^\/assets\/sub\/portrait\.png\?v=[a-f0-9]{8}$/');
    expect($image->url(bust: false))->toBe('/assets/sub/portrait.png');
    expect($image->url(host: 'http://example.com/'))->toMatch(
        '/^http:\/\/example\.com\/assets\/sub\/portrait\.png\?v=[a-f0-9]{8}$/'
    );
    expect($image->url(bust: false, host: 'http://example.com/'))->toBe(
        'http://example.com/assets/sub/portrait.png'
    );
});


test('Static cache route', function () {
    $router = new Router();
    $router->addStatic('cache', '/cache/assets', C::root() . C::DS .
        'public' . C::DS . 'cache' . C::DS . 'assets');
    $assets = new Assets(
        $this->paths['assets'],
        $this->paths['cache'],
        $this->request(router: $router)
    );
    $image = $assets->image($this->portrait)->resize(200);

    expect(is_file($image->path()))->toBe(true);
    expect($image->url())->toMatch('/^\/cache\/assets\/sub\/portrait-w200b\.png\?v=[a-f0-9]{8}$/');
    expect($image->url(bust: false))->toBe('/cache/assets/sub/portrait-w200b.png');
    expect($image->url(host: 'http://example.com/'))->toMatch(
        '/^http:\/\/example\.com\/cache\/assets\/sub\/portrait-w200b\.png\?v=[a-f0-9]{8}$/'
    );
    expect($image->url(bust: false, host: 'http://example.com/'))->toBe(
        'http://example.com/cache/assets/sub/portrait-w200b.png'
    );

    $image->delete();

    expect(is_file($image->path()))->toBe(false);
});
