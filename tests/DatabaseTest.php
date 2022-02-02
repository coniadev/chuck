<?php

declare(strict_types=1);

use Chuck\Testing\DatabaseCase;
use Chuck\Model\Database;

uses(DatabaseCase::class);


test('database', function () {
    $db = new Database($this->getTestDbDsn());

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});
