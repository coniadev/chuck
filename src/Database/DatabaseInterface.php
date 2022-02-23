<?php

declare(strict_types=1);

namespace Chuck\Database;

use \PDO;

use Chuck\ConfigInterface;


interface DatabaseInterface
{
    public function __construct(ConfigInterface $config);

    public function defaultFetchMode(int $fetchMode): self;
    public function getFetchMode(): int;

    public function addScriptDir(string $dir): self;
    public function getScriptDirs(): array;

    public function setPrintQuery(bool $shouldPrint): self;
    public function shouldPrintQuery(): bool;

    public function getMemcached(): ?\Chuck\Memcached;

    // Database operations
    public function connect(): self;
    public function getConn(): PDO;
    public function begin(): bool;
    public function commit(): bool;
    public function rollback(): bool;
    public function execute(string $query, mixed ...$args): QueryInterface;
    public function __get(string $key): Folder;
}