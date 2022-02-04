<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\ConfigInterface;


interface DatabaseInterface
{
    public function __construct(ConfigInterface $config);

    public function defaultFetchMode(int $fetchMode): self;
    public function getFetchMode(): int;

    public function addScriptDirs(array|string $dirs): self;
    public function getScriptDirs(): array;

    public function setPrintScript(bool $shouldPrint): self;
    public function shouldPrintScript(): bool;

    public function memcachedConfig(array $settings): self;
    public function getMemcached(): ?\Memcached;

    // Database operations
    public function getConn(): PDO;
    public function begin(): bool;
    public function commit(): bool;
    public function rollback(): bool;
    public function execute(string $query, ...$args): QueryInterface;
    public function __get($key): Folder;
}
