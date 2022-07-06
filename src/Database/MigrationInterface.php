<?php

declare(strict_types=1);

namespace Conia\Chuck\Database;

use Conia\Chuck\ConfigInterface;
use Conia\Chuck\Config\Connection;
use Conia\Chuck\Database\DatabaseInterface;


interface MigrationInterface
{
    public function run(DatabaseInterface $db, ConfigInterface $config, Connection $conn): void;
}
