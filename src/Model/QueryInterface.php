<?php

declare(strict_types=1);

namespace Chuck\Model;


interface QueryInterface
{
    public function __construct(DatabaseInterface $db, string $script, array $args);
    public function one(int $fetchMode = null): ?array;
    public function item(int $fetchMode = null): ?Item;
    public function all(int $fetchMode = null): iterable;
    public function items(int $fetchMode = null): iterable;
    public function run(): bool;
    public function len(): int;
    public function interpolate($query, $args): string;
}
