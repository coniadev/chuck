<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Cli\Runner;

uses(TestCase::class);


afterEach(function () {
    // Each Runner::run call registers a error handler
    restore_error_handler();
    restore_exception_handler();
});


test('Show help when called without command', function () {
    $_SERVER['argv'] = ['run'];

    ob_start();
    $result = Runner::run($this->app());
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(0);
    expect($content)->toContain('Available commands');
});


test('List commands', function () {
    $_SERVER['argv'] = ['run', 'commands'];

    ob_start();
    $result = Runner::run($this->app());
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(0);
    expect($content)->toBe("add-migration\ncreate-migrations-table\nmigrations\nserver\n");
});


test('Command not found', function () {
    $_SERVER['argv'] = ['run', 'unknown-command'];

    ob_start();
    $result = Runner::run($this->app());
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(1);
    expect($content)->toContain('Command not found');
});


test('Pass additional dir', function () {
    $_SERVER['argv'] = ['run', 'commands'];

    ob_start();
    $result = Runner::run($this->app(), [C::root() . C::DS . 'scripts']);
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(0);
    expect($content)->toContain('add-migration');
    expect($content)->toContain('error-script');
});


test('Handle script error', function () {
    $_SERVER['argv'] = ['run', 'error-script'];

    ob_start();
    $result = Runner::run($this->app(), [C::root() . C::DS . 'scripts']);
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(1);
    expect($content)->toContain('error-script');
    expect($content)->toContain('script error');
});
