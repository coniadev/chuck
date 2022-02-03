<?php

declare(strict_types=1);

use Chuck\Tests\DatabaseCase;
use Chuck\Model\Database;

uses(DatabaseCase::class);

const ds = DIRECTORY_SEPARATOR;
const ADDITIONAL_SCRIPTS = __DIR__ . ds . 'fixtures' . ds . 'sql' . ds . 'expand';
const NUMBER_OF_ALBUMS = 7;
const NUMBER_OF_MEMBERS = 17;


test('Database connection', function () {
    $db = new Database($this->getConfig());

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});


test('Database connection single script dir', function () {
    $db = $this->getDb();
    $result = $db->members->list()->all();

    expect(count($result))->toBe(NUMBER_OF_MEMBERS);
});


test('Query with question mark parameters', function () {
    $db = $this->getDb();
    $result = $db->members->byId(2)->one();

    expect($result['name'])->toBe('Rick Rozz');
});


test('Expand script dirs :: query from default', function () {
    $db = new Database($this->getConfig());
    $db->addScriptDirs(ADDITIONAL_SCRIPTS);

    $result = $db->members->list()->all();
    expect(count($result))->toBe(NUMBER_OF_MEMBERS);
});


test('Expand script dirs :: query from expanded', function () {
    $db = new Database($this->getConfig());
    $db->addScriptDirs(ADDITIONAL_SCRIPTS);

    $result = $db->members->byName(['name' => 'Rick Rozz'])->one();
    expect($result['member'])->toBe(2);
});


test('Expand script dirs :: query from expanded new namespace', function () {
    $db = new Database($this->getConfig());
    $db->addScriptDirs(ADDITIONAL_SCRIPTS);

    $result = $db->albums->list()->all();
    expect(count($result))->toBe(7);
});
