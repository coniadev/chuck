<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Config;

uses(TestCase::class);


test('Defaults', function () {
    $config = new Config($this->minimalOptions());

    expect($config->get('port'))->toBe(1983);
    expect($config->path('root'))->toBe(realpath(__DIR__ . DIRECTORY_SEPARATOR . 'fixtures'));
});


test('Custom options', function () {
    $config = new Config($this->options([
        'album' => 'Symbolic',
    ]));

    expect($config->get('port'))->toBe(1983);
    expect($config->get('album'))->toBe('Symbolic');
});


test('Host and origin', function () {
    $config = new Config($this->minimalOptions());

    expect($config->get('origin'))->toBe('http://localhost:1983');
    expect($config->get('host'))->toBe('localhost');
});


test('Default value', function () {
    $config = new Config($this->minimalOptions());

    expect($config->get('missing', 'default'))->toBe('default');
});


test('Missing key', function () {
    $config = new Config($this->minimalOptions());

    $config->get('missing');
})->throws(\InvalidArgumentException::class);


test('Template paths', function () {
    $config = new Config($this->options([
        // templates.default is defined in $this->options()
        'templates.relative' => 'templates/additional',
    ]));
    $prefix = $this->root . DIRECTORY_SEPARATOR . 'templates' . DIRECTORY_SEPARATOR;

    expect($config->path('templates')['default'])->toBe($prefix . 'default');
    expect($config->path('templates')['relative'])->toBe($prefix . 'additional');
});


test('Migrations paths', function () {
    $config = new Config($this->options([
        'migrations.absolute' => $this->root . DIRECTORY_SEPARATOR . 'migrations' . DIRECTORY_SEPARATOR . 'default',
        'migrations.relative' => 'migrations' . DIRECTORY_SEPARATOR . 'additional',
    ]));
    $prefix = $this->root . DIRECTORY_SEPARATOR . 'migrations' . DIRECTORY_SEPARATOR;

    expect($config->path('migrations'))->toBe([
        $prefix . 'default',
        $prefix . 'additional',
    ]);
});
