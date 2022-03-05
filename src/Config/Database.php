<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;
use Chuck\Util\Arrays;


class Database
{
    use PathTrait;

    protected array $connections = [];
    protected array $sql = [];
    protected array $migrations = [];

    public function __construct(protected string $root)
    {
    }

    public function setConnections(array $connections): void
    {
        $this->connections = $connections;
    }

    public function setSql(array $sql): void
    {
        $clean = [];

        foreach ($sql as $section => $paths) {
            // e. g. 'sql' => 'path/to/sql'
            if (is_string($paths)) {
                $clean[$section] = ['all' => $this->preparePath($paths)];
                continue;
            }

            if (!Arrays::isAssoc($paths)) {
                throw new ValueError(
                    "The 'sql' setting in the config file must be a string or an associative array"
                );
            }

            foreach ($paths as $driver => $path) {
                $clean[$section][$driver] = $this->preparePath($path);
            }
        }

        $this->sql = $clean;
    }

    public function setMigrations(array $migrations): void
    {
        $this->migrations = $migrations;
    }

    public function connection(string $connection, string $sql): Connection
    {
        return new Connection(
            $this->connections[$connection],
            $this->sql[$sql]
        );
    }

    public function migrations(): array
    {
        return array_map(
            fn ($m) => $this->preparePath($m),
            array_values($this->migrations)
        );
    }
}
