<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Util\Path;

uses(TestCase::class);


test('Path realpath', function () {
    expect(
        Path::realpath('/perserverance/./of/././the/../time')
    )->toBe('/perserverance/of/time');
    expect(
        Path::realpath('spiritual/../../../healing')
    )->toBe('healing');
    expect(
        Path::realpath('\\\\///perserverance//\\.\\/of/.///./the//../\\\\time\\\\', separator: '/')
    )->toBe('/perserverance/of/time/');
});


test('Path is inside root dir', function () {
    $config = $this->config();
    $pathUtil = new Path($config);

    expect($pathUtil->insideRoot(C::root() . "/../leprosy"))->toBe(false);
    expect($pathUtil->insideRoot(C::root() . "/symbolic"))->toBe(true);
    expect($pathUtil->insideRoot(C::root() . "/././/./symbolic"))->toBe(true);
    expect($pathUtil->insideRoot(C::root() . "/./..//./symbolic"))->toBe(false);
    expect($pathUtil->insideRoot("/etc/apache"))->toBe(false);
});