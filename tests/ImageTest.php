<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Image;


uses(TestCase::class);


beforeEach(function () {
    $this->paths = [
        'path.assets.files' => 'public' . C::DS . 'assets',
        'path.assets.cache' => 'public' . C::DS . 'cache' . C::DS . 'assets',
    ];
});



test('Create from config', function () {
    $image = Image::fromConfig('large.png', $this->config($this->paths));

    expect($image->get())->toBeInstanceOf(GdImage::class);
});
