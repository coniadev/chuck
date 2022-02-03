<?php

declare(strict_types=1);

use Chuck\Tests\DatabaseCase;
use Chuck\Model\Database;

uses(DatabaseCase::class);

const ds = DIRECTORY_SEPARATOR;
const ADDITIONAL_SCRIPTS = __DIR__ . ds . 'fixtures' . ds . 'sql' . ds . 'expand';


test('Database connection', function () {
    $db = new Database($this->getConfig());

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});


test('Database connection single script dir', function () {
    $db = $this->getDb();
    $result = $db->users->list()->all();

    expect(count($result))->toBe(3);
});


test('Database connection expand script dirs', function () {
    $db = new Database($this->getConfig());
    $db->addScriptDirs(ADDITIONAL_SCRIPTS);

    // User query from original dir
    $result = $db->users->list()->all();
    expect(count($result))->toBe(3);

    // User query from additional dir
    $result = $db->users->byId(['user' => 1])->one();
    expect($result['name'])->toBe('Chuck Schuldiner');

    // Additional query from new namespace albums
    $result = $db->albums->list()->all();
    expect(count($result))->toBe(7);

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});
