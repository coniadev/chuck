<?php

declare(strict_types=1);

use Conia\Chuck\Cli\Opts;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);

beforeEach(function () {
    $_SERVER['argv'] = [
        'run',
        'migrations',
        '--list',
        '1',
        'chuck',
        '-h',
        '--conn',
        'sqlite',
        '--novalues',
    ];
});


test('Has option', function () {
    $opts = new Opts();

    expect($opts->has('run'))->toBe(false);
    expect($opts->has('migrations'))->toBe(false);
    expect($opts->has('-h'))->toBe(true);
    expect($opts->has('--conn'))->toBe(true);
});


test('Get value', function () {
    $opts = new Opts();

    expect($opts->get('--conn'))->toBe('sqlite');
    expect($opts->get('--conn', 'pgsql'))->toBe('sqlite');
    expect($opts->get('-h', 'default'))->toBe('default');
    expect($opts->get('-?', 'default'))->toBe('default');
});


test('Get values', function () {
    $opts = new Opts();

    expect($opts->all('--list'))->toBe(['1', 'chuck']);
    expect($opts->all('--list', ['2']))->toBe(['1', 'chuck']);
    expect($opts->all('--conn'))->toBe(['sqlite']);
    expect($opts->all('--novalues', ['1', '2']))->toBe(['1', '2']);
    expect($opts->all('--missing', ['1', '2']))->toBe(['1', '2']);
});


test('Try to get value from missing option', function () {
    $opts = new Opts();

    $opts->get('-?');
})->throws(ValueError::class, 'Unknown option: -?');


test('Try to get values from missing option', function () {
    $opts = new Opts();

    $opts->all('--missing');
})->throws(ValueError::class, 'Unknown option: --missing');

test('Try to get missing value', function () {
    $opts = new Opts();

    $opts->get('-h');
})->throws(ValueError::class, 'No value given for -h');


test('Try to get missing values', function () {
    $opts = new Opts();

    $opts->all('--novalues');
})->throws(ValueError::class, 'No value given for --novalues');
