<?php

/**
 * Migration testing is complex.
 *
 * Some of these tests depend on each other and the order
 * in which they are executed. So reorganize with care.
 */

declare(strict_types=1);

use Chuck\Tests\Setup\{DatabaseCase, C};
use Chuck\Cli\Runner;

uses(DatabaseCase::class);


beforeAll(function () {
    // Remove remnants of previous runs
    $migrationsDir = C::root() . C::DS . 'migrations' . C::DS;
    array_map('unlink', glob("$migrationsDir*test-migration*"));

    DatabaseCase::cleanupTestDbs();
});


dataset('connections', DatabaseCase::getAvailableDsns());
dataset('transaction-connections', DatabaseCase::getAvailableDsns(transactionsOnly: true));


test('Run migrations :: no migrations table', function () {
    $_SERVER['argv'] = ['run', 'migrations', '--apply'];

    ob_start();
    $result = Runner::run($this->config());
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(false);
    expect($content)->toContain('Migrations table does not exist');
});


test('Create migrations table :: success', function (string $dsn) {
    $_SERVER['argv'] = ['run', 'create-migrations-table'];

    ob_start();
    $result = Runner::run($this->config(['db' => ['dsn' => $dsn]]));
    ob_end_clean();

    expect($result)->toBe(true);
})->with('connections');


test('Create migrations table :: already exists', function () {
    $_SERVER['argv'] = ['run', 'create-migrations-table'];

    ob_start();
    $result = Runner::run($this->config());
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(false);
    expect($content)->toContain("Table 'migrations' already exists");
});


test('Run migrations :: success without apply', function (string $dsn) {
    $_SERVER['argv'] = ['run', 'migrations'];

    ob_start();
    $result = Runner::run($this->config(['db' => ['dsn' => $dsn]]));
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(true);
    expect($content)->toMatch('/000000-000000-migration.sql[^\n]*?success/');
    expect($content)->toMatch('/000000-000001-migration.php[^\n]*?success/');
    expect($content)->toMatch('/000000-000002-migration.tpql[^\n]*?success/');
    expect($content)->toContain('Would apply 3 migrations');
})->with('transaction-connections');


test('Run migrations :: success', function (string $dsn) {
    $_SERVER['argv'] = ['run', 'migrations', '--apply'];

    ob_start();
    $result = Runner::run($this->config(['db' => ['dsn' => $dsn]]));
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(true);
    expect($content)->toMatch('/000000-000000-migration.sql[^\n]*?success/');
    expect($content)->toMatch('/000000-000001-migration.php[^\n]*?success/');
    expect($content)->toMatch('/000000-000002-migration.tpql[^\n]*?success/');
    expect($content)->toContain('3 migrations successfully applied');
})->with('connections');


test('Run migrations :: again', function (string $dsn) {
    $_SERVER['argv'] = ['run', 'migrations', '--apply'];

    ob_start();
    $result = Runner::run($this->config(['db' => ['dsn' => $dsn]]));
    $content = ob_get_contents();
    ob_end_clean();

    expect($result)->toBe(true);
    expect($content)->not->toMatch('/000000-000000-migration.sql[^\n]*?success/');
    expect($content)->toContain('No migrations applied');
})->with('connections');


test('Add migration SQL', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '--file', 'test migration'];

    ob_start();
    $migration = Runner::run($this->config());
    ob_end_clean();

    expect(is_file($migration))->toBe(true);
    expect(str_starts_with($migration, C::root()))->toBe(true);
    expect(str_ends_with($migration, '.sql'))->toBe(true);

    // Add content and run it
    file_put_contents($migration, 'SELECT 1;');
    $_SERVER['argv'] = ['run', 'migrations', '--apply'];

    ob_start();
    $result = Runner::run($this->config());
    $content = ob_get_contents();
    ob_end_clean();
    @unlink($migration);
    expect(is_file($migration))->toBe(false);

    expect($result)->toBe(true);
    expect($content)->toMatch('/' . basename($migration) . '[^\n]*?success/');
    expect($content)->toContain('1 migration successfully applied');
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
    expect($content)->toContain("implements MigrationInterface");
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

    expect($output)->toContain("The migrations directory does not exist");
});


test('Add migration to vendor', function () {
    $_SERVER['argv'] = ['run', 'add-migration', '-f', 'test'];

    ob_start();
    Runner::run($this->config(['migrations' => 'vendor' . C::DS . 'migrations']));
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toContain("is inside './vendor'");
});


test('Failing SQL migration', function ($dsn, $ext) {
    $_SERVER['argv'] = ['run', 'add-migration', '--file', "test-migration-failing$ext"];

    ob_start();
    $migration = Runner::run($this->config(['db' => ['dsn' => $dsn]]));

    // Add content and run it
    file_put_contents($migration, 'RUBBISH;');
    $_SERVER['argv'] = ['run', 'migrations', '--apply'];

    $result = Runner::run($this->config(['db' => ['dsn' => $dsn]]));
    $content = ob_get_contents();
    ob_end_clean();
    @unlink($migration);
    expect(is_file($migration))->toBe(false);

    expect($result)->toBe(false);

    if (str_starts_with($dsn, 'mysql')) {
        expect($content)->toContain('0 migration applied until the error occured');
    } else {
        expect($content)->toContain('Due to errors no migrations applied');
    }
})->with('connections')->with(['.sql', '.tpql']);


test('Failing TPQL/PHP migration (PHP error)', function ($dsn, $ext) {
    $_SERVER['argv'] = ['run', 'add-migration', '--file', "test-migration-php-failing.$ext"];

    ob_start();
    $migration = Runner::run($this->config(['db' => ['dsn' => $dsn]]));

    // Add content and run it
    file_put_contents($migration, '<?php echo if)');
    $_SERVER['argv'] = ['run', 'migrations', '--apply'];

    $result = Runner::run($this->config(['db' => ['dsn' => $dsn]]));
    $content = ob_get_contents();
    ob_end_clean();
    @unlink($migration);
    expect(is_file($migration))->toBe(false);

    expect($result)->toBe(false);

    if (str_starts_with($dsn, 'mysql')) {
        expect($content)->toContain('0 migration applied until the error occured');
    } else {
        expect($content)->toContain('Due to errors no migrations applied');
    }
})->with('connections')->with(['.php', '.tpql']);
