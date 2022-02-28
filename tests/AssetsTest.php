<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Asset;


uses(TestCase::class);


beforeEach(function () {
    $this->paths = [
        'path.assets.files' => 'public' . C::DS . 'assets',
        'path.assets.cache' => 'public' . C::DS . 'cache' . C::DS . 'assets',
    ];
});


test('Create instance from config', function () {
    $asset = Asset::fromConfig($this->config($this->paths));

    expect($asset)->toBeInstanceOf(Asset::class);
});
