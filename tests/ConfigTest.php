<?php

declare(strict_types=1);

use Conia\Chuck\Config;
use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Exception\ValueError;
use Conia\Chuck\Logger;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Defaults', function () {
    $config = new Config('chuck');

    expect($config->app())->toBe('chuck');
    expect($config->debug())->toBe(false);
    expect($config->env())->toBe('');
    expect($config->app)->toBe('chuck');
    expect($config->debug)->toBe(false);
    expect($config->env)->toBe('');
});

test('Init values', function () {
    $config = new Config('chuck', true, 'prod');

    expect($config->app())->toBe('chuck');
    expect($config->debug())->toBe(true);
    expect($config->env())->toBe('prod');
    expect($config->app)->toBe('chuck');
    expect($config->debug)->toBe(true);
    expect($config->env)->toBe('prod');
});

test('Wrong app name', function () {
    new Config('wrong name');
})->throws(ValueError::class, 'app name');


test('Custom options', function () {
    $config = new Config('chuck');
    $config->set('album', 'Symbolic');

    expect($config->has('album'))->toBe(true);
    expect($config->get('album'))->toBe('Symbolic');
});


test('Default value', function () {
    $config = new Config('chuck');

    expect($config->get('missing', 'default'))->toBe('default');
});


test('Missing key', function () {
    $config = new Config('chuck');

    $config->get('missing');
})->throws(OutOfBoundsException::class, 'does not exist');
