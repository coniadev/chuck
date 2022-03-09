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
        protected array $migrations,
    ) {
        $this->sql = $this->getSql($sql);
    }


    protected function getSql(array $sql): array
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

        return $clean;
    }

    public function connection(
        string $connection = Config::DEFAULT,
        string $sql = Config::DEFAULT,
    ): Connection {
        return Connection::fromArray(
            $this->connections[$connection],
            // Allow only an empty list of sql dirs if the default section is used
            $sql === Config::DEFAULT ? $this->sql[Config::DEFAULT] ?? [] : $this->sql[$sql],
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
