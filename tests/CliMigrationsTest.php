<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Cli\Runner;

uses(TestCase::class);


test('Add migration SQL', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '--file', 'test migration'];

    ob_start();
    $migration = Runner::run($this->config());
    ob_end_clean();

    expect(is_file($migration))->toBe(true);
    expect(str_starts_with($migration, C::root()))->toBe(true);
    expect(str_ends_with($migration, '.sql'))->toBe(true);

    @unlink($migration);
    expect(is_file($migration))->toBe(false);
});

test('Add migration TPQL', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '--file', 'test migration.tpql'];

    ob_start();
    $migration = Runner::run($this->config());
    ob_end_clean();

    expect(is_file($migration))->toBe(true);
    expect(str_starts_with($migration, C::root()))->toBe(true);
    expect(str_ends_with($migration, '.tpql'))->toBe(true);
    expect(strpos($migration, '.sql'))->toBe(false);

    $content = file_get_contents($migration);

    @unlink($migration);
    expect(is_file($migration))->toBe(false);
    expect($content)->toContain('<?php if');
});

test('Add migration PHP', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '--file', 'test migration.php'];

    ob_start();
    $migration = Runner::run($this->config());
    ob_end_clean();

    expect(is_file($migration))->toBe(true);
    expect(str_starts_with($migration, C::root()))->toBe(true);
    expect(str_ends_with($migration, '.php'))->toBe(true);
    expect(strpos($migration, '.sql'))->toBe(false);

    $content = file_get_contents($migration);

    @unlink($migration);
    expect(is_file($migration))->toBe(false);
    expect($content)->toContain("TestMigration_");
    expect($content)->toContain("extends Migration");
});


test('Add migration with wrong file extension', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '-f', 'test.exe'];

    ob_start();
    Runner::run($this->config());
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toContain("Wrong file extension");
});


test('Wrong migrations directory', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '-f', 'test'];

    ob_start();
    Runner::run($this->config(['migrations' => 'not' . C::DS . 'available']));
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toContain("Migrations directory does not exits");
});


test('Add migration to vendor', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '-f', 'test'];

    ob_start();
    Runner::run($this->config(['migrations' => 'vendor' . C::DS . 'migrations']));
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toContain("is inside './vendor'");
});