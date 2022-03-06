<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Cli\Runner;

uses(TestCase::class);


test('Add migration SQL', function () {
    $_SERVER['argv'] = [
        'run',
        'add-migration',
        'test migration',
    ];

    ob_start();
    $migration = Runner::run($this->config());
    ob_end_clean();

    expect(is_file($migration))->toBe(true);
    expect(str_starts_with($migration, C::root()))->toBe(true);
    expect(str_ends_with($migration, '.sql'))->toBe(true);

    @unlink($migration);
    expect(is_file($migration))->toBe(false);
});
