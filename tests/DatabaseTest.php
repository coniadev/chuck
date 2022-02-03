<?php

declare(strict_types=1);

use Chuck\Tests\DatabaseCase;
use Chuck\Model\Database;

uses(DatabaseCase::class);


test('Database connection', function () {
    $db = new Database($this->getConfig());

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});

test('Database query', function () {
    $db = $this->getDb();
    $result = $db->users->all()->all();

    expect(count($result))->toBe(3);
});
