<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\ConfigInterface;


interface DatabaseInterface
{
    public function __construct(
        protected string $dsn,
        protected ?string $username = null,
        protected ?string $password = null,
        protected ?array $options = null,
    );
    public static function fromConfig(ConfigInterface $config): self;
    public function printSql(bool $shouldPrint): DatabaseInterface;
    public function setDefaultFetchMode(int $fetchMode): DatabaseInterface;
    public function addScriptPaths(array|string $paths): void;
    public function getScriptPaths(): array;
    public function begin(): bool;
    public function commit(): bool;
    public function rollback(): bool;
    public function getConn(): PDO;
    public function getMemcached(): ?\Memcached;
    public function __get($key): Folder;
    public function getFetchMode(): int;
    public function encode(int $id): string;
    public function encodeList(iterable $list, array|string $hashKey, bool $asUid = false): \Generator;
    public function decode(string $uid): int;
}
