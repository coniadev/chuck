<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;
use Chuck\Config;
use Chuck\Util\Arrays;


class Database
{
    use PathTrait;

    protected array $sql = [];

    public function __construct(
        protected readonly string $root,
        protected array $connections,
        array $sql,
        protected array $migrations = [],
    ) {
        $this->sql = $this->prepareSql($sql);
    }

    public function connection(
        string $connection = Config::DEFAULT,
        string $sql = Config::DEFAULT,
    ): Connection {
        return Connection::fromArray(
            $this->connections[$connection],
            // Allow only an empty list of sql dirs if the default section is used
            $sql === Config::DEFAULT ?
                $this->sql[Config::DEFAULT] ?? [] :
                $this->sql[$sql],
        );
    }
}
