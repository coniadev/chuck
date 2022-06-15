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
    $ds = DIRECTORY_SEPARATOR;

    expect($pathUtil->inside(C::root(), C::root() . "$ds..{$ds}leprosy"))->toBe(false);
    expect($pathUtil->inside(C::root(), C::root() . "{$ds}symbolic"))->toBe(true);
    expect($pathUtil->inside(C::root(), C::root() . "$ds.$ds.$ds$ds.{$ds}symbolic"))->toBe(true);
    expect($pathUtil->inside(C::root(), C::root() . "$ds.$ds..$ds$ds.{$ds}symbolic"))->toBe(false);
    expect($pathUtil->inside(C::root(), "{$ds}etc{$ds}apache"))->toBe(false);
});
