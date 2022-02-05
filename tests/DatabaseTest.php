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


test('Database init set fetch mode via method', function () {
    $db = new Database($this->getConfig());

    $result = $db->defaultFetchMode(\PDO::FETCH_ASSOC);

    expect($db->getFetchmode())->toBe(\PDO::FETCH_ASSOC);
    expect($result)->toBeInstanceOf(Database::class);
});


test('Query with question mark parameters', function () {
    $db = $this->getDb();
    $result = $db->members->byId(2)->one();
    expect($result['name'])->toBe('Rick Rozz');

    // arguments can also be passed as array
    $result = $db->members->byId([4])->one();
    expect($result['name'])->toBe('Terry Butler');
});


test('Query with named parameters', function () {
    $db = $this->getDb();
    $result = $db->members->activeFromTo([
        'from' => 1990,
        'to' => 1995,
    ])->all();

    expect(count($result))->toBe(7);
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


test('Multiple Query->one calls', function () {
    $db = new Database($this->getConfig());
    $query = $db->members->activeFromTo([
        'from' => 1990,
        'to' => 1995,
    ]);

    $i = 0;
    $result = $query->one();
    while ($result) {
        $i++;
        $result = $query->one();
    }

    expect($i)->toBe(7);
});


test('Databse::execute', function () {
    $db = new Database($this->getConfig());
    $query = 'SELECT * FROM albums';

    expect(count($db->execute($query)->all()))->toBe(7);
});


test('Databse::execute with args', function () {
    $db = new Database($this->getConfig());
    $queryQmark = 'SELECT name FROM members WHERE joined = ? AND left = ?';
    $queryNamed = 'SELECT name FROM members WHERE joined = :joined AND left = :left';

    expect(
        $db->execute($queryQmark, [1991, 1992])->one()['name']
    )->toBe('Sean Reinert');

    expect(
        $db->execute($queryQmark, 1991, 1992)->one()['name']
    )->toBe('Sean Reinert');

    expect(
        $db->execute($queryNamed, ['left' => 1992, 'joined' => 1991])->one()['name']
    )->toBe('Sean Reinert');
});


test('Script dir shadowing', function () {
    $db = $this->getDb();

    // The query in the default dir uses question mark parameters
    // and returns the field `left` additionally to `member` and `name`.
    $result = $db->members->byId(2)->one();
    expect($result['name'])->toBe('Rick Rozz');
    expect($result['left'])->toBe(1989);

    // The query in the expand dir uses named parameters
    // and additionally returns the field `joined` in contrast
    // to the default dir, which returns the field `left`.
    $db->addScriptDirs(ADDITIONAL_SCRIPTS);
    // Named parameter queries also support positional arguments
    $result = $db->members->byId(3)->one();
    expect($result['name'])->toBe('Chris Reifert');
    expect($result['joined'])->toBe(1986);
    // Passed named args
    $result = $db->members->byId(['member' => 4])->one();
    expect($result['name'])->toBe('Terry Butler');
    expect($result['joined'])->toBe(1987);
});


test('Accessing non-existent namespace (Folder)', function () {
    $db = $this->getDb();
    $db->doesNotExist;
})->throws(\UnexpectedValueException::class);


test('Accessing non-existent script/query', function () {
    $db = $this->getDb();
    $db->members->doesNotExist;
})->throws(\UnexpectedValueException::class);
