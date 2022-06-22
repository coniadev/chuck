<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{DatabaseCase, C};
use Chuck\Config\Connection;

uses(DatabaseCase::class);


test('Initialization', function () {
    $dsn = $this->getDsn();
    $sql = $this->getSqlDirs();
    $conn = new Connection($dsn, $sql);

    expect($conn->dsn())->toBe($dsn);
    expect(realpath($conn->sql()[0]))->toBe(realpath($sql));
    expect($conn->print())->toBe(false);
    expect($conn->print(true))->toBe(true);
});


test('Driver specific dir', function () {
    $conn = new Connection($this->getDsn(), [
        'all' => C::root() . C::DS . 'sql' . C::DS . 'default',
        'sqlite' => C::root() . C::DS . 'sql' . C::DS . 'additional',
        'ignored' => C::root() . C::DS . 'sql' . C::DS . 'ignored',
    ]);

    $sql = $conn->sql();
    expect(count($sql))->toBe(2);
    // Driver specific must come first
    expect($sql[0])->toEndWith('/additional');
    expect($sql[1])->toEndWith('/default');
});


test('Add SQL dirs later', function () {
    $conn = new Connection(
        $this->getDsn(),
        C::root() . C::DS . 'sql' . C::DS . 'default',
    );

    $conn->addSqlDirs([
        'sqlite' => C::root() . C::DS . 'sql' . C::DS . 'additional',
        'ignored' => C::root() . C::DS . 'sql' . C::DS . 'ignored',
    ]);

    $sql = $conn->sql();
    expect(count($sql))->toBe(2);
    // Driver specific must come first
    expect($sql[0])->toEndWith('/additional');
    expect($sql[1])->toEndWith('/default');
});


test('Mixed dirs format', function () {
    $conn = new Connection(
        $this->getDsn(),
        [
            [
                'all' => C::root() . C::DS . 'sql' . C::DS . 'default',
                'sqlite' => C::root() . C::DS . 'sql' . C::DS . 'additional',
                'ignored' => C::root() . C::DS . 'sql' . C::DS . 'ignored',
            ],
            C::root() . C::DS . 'sql' . C::DS . 'additional' . C::DS . 'members',
        ]
    );

    $sql = $conn->sql();
    expect(count($sql))->toBe(3);
    expect($sql[0])->toEndWith('/members');
    expect($sql[1])->toEndWith('/additional');
    expect($sql[2])->toEndWith('/default');
});


test('Wrong sql format', function () {
    new Connection($this->getDsn(), [
        C::root() . C::DS . 'sql' . C::DS . 'default',
        [
            C::root() . C::DS . 'sql' . C::DS . 'additional',
            C::root() . C::DS . 'sql' . C::DS . 'ignored',
        ]
    ]);
})->throws(ValueError::class, 'string or an associative array');


test('Migration directories', function () {
    $conn = new Connection(
        $this->getDsn(),
        C::root() . C::DS . 'sql' . C::DS . 'default',
        [C::root() . C::DS . 'migrations', C::root() . C::DS . 'sql' . C::DS . 'additional']
    );
    $migrations = $conn->migrations();

    expect(count($migrations))->toBe(2);
    expect($migrations[0])->toEndWith('/additional');
    expect($migrations[1])->toEndWith('/migrations');
});


test('Agg migration directories later', function () {
    $conn = new Connection(
        $this->getDsn(),
        C::root() . C::DS . 'sql' . C::DS . 'default',
    );
    $conn->addMigrationDirs([
        C::root() . C::DS . 'migrations',
        C::root() . C::DS . 'sql' . C::DS . 'additional'
    ]);
    $migrations = $conn->migrations();

    expect(count($migrations))->toBe(2);
    expect($migrations[0])->toEndWith('/additional');
    expect($migrations[1])->toEndWith('/migrations');
});


test('Unsupported dsn', function () {
    new Connection('notsupported:host=localhost;dbname=chuck', $this->getSqlDirs());
})->throws(RuntimeException::class, 'driver not supported');


test('Migration table setting', function () {
    $conn = new Connection($this->getDsn(), $this->getSqlDirs());

    expect($conn->migrationsTable())->toBe('migrations');
    expect($conn->migrationsColumnMigration())->toBe('migration');
    expect($conn->migrationsColumnApplied())->toBe('applied');

    $conn->setMigrationsTable('newmigrations');
    $conn->setMigrationsColumnMigration('newmigration');
    $conn->setMigrationsColumnApplied('newapplied');

    expect($conn->migrationsTable())->toBe('newmigrations');
    expect($conn->migrationsColumnMigration())->toBe('newmigration');
    expect($conn->migrationsColumnApplied())->toBe('newapplied');
});


test('Wrong migrations table name', function () {
    $conn = new Connection($this->getDsn(), $this->getSqlDirs());
    $conn->setMigrationsTable('new migrations');
    $conn->migrationsTable();
})->throws(ValueError::class, 'Invalid migrations table name');


test('Wrong migration column name', function () {
    $conn = new Connection($this->getDsn(), $this->getSqlDirs());
    $conn->setMigrationsColumnMigration('new migration');
    $conn->migrationsColumnMigration();
})->throws(ValueError::class, 'Invalid migrations table column name');


test('Wrong applied column name', function () {
    $conn = new Connection($this->getDsn(), $this->getSqlDirs());
    $conn->setMigrationsColumnApplied('new migration');
    $conn->migrationsColumnApplied();
})->throws(ValueError::class, 'Invalid migrations table column name');
