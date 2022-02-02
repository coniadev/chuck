<?php

declare(strict_types=1);

use Chuck\Tests\DatabaseCase;
use Chuck\Model\Database;

uses(DatabaseCase::class);


test('Database connection', function () {
    $db = new Database($this->getDsn());

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});

test('Database connection via config', function () {
    $db = Database::fromConfig($this->getConfig());

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});
