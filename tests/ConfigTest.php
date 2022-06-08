<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Config;
use Chuck\Logger;

uses(TestCase::class);


test('Defaults', function () {
    $config = new Config('chuck', C::root());

    expect($config->app())->toBe('chuck');
    expect($config->root())->toBe(C::root());
    expect($config->public())->toBe(C::root() . DIRECTORY_SEPARATOR . 'public');
});


test('Root path not absolute', function () {
    new Config('chuck', 'no/absolute/path');
})->throws(ValueError::class, 'must be an absolute');


test('Public not determinable', function () {
    new Config('chuck', C::root() . C::DS . 'altroot');
})->throws(ValueError::class, 'not be determined');


test('Public set', function () {
    $config = new Config('chuck', C::root() . C::DS . 'altroot', 'www');

    expect($config->public())->toBe(realpath(
        C::root() . C::DS . 'altroot' . C::DS . 'www'
    ));
});


test('Custom options', function () {
    $config = new Config('chuck', C::root());
    $config->set('album', 'Symbolic');

    expect($config->has('album'))->toBe(true);
    expect($config->get('album'))->toBe('Symbolic');
});


test('Default value', function () {
    $config = new Config('chuck', C::root());

    expect($config->get('missing', 'default'))->toBe('default');
});


test('Missing key', function () {
    $config = new Config('chuck', C::root());

    $config->get('missing');
})->throws(InvalidArgumentException::class, 'does not exist');


test('Logger setup', function () {
    $config = new Config('chuck', C::root());
    $config->setupLogger(function () {
        $logfile = C::root() . C::DS . 'log' . C::DS . bin2hex(random_bytes(4)) . '.log';
        return new Logger(Logger::DEBUG, $logfile);
    });

    expect($config->logger())->toBeInstanceOf(Logger::class);
});
