<?php

declare(strict_types=1);

namespace Chuck\Database;

use Chuck\ConfigInterface;
use Chuck\Config\Connection;
use Chuck\Database\DatabaseInterface;


interface MigrationInterface
{
    public function run(DatabaseInterface $db, ConfigInterface $config, Connection $conn): void;
}
