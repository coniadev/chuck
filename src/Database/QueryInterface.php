<?php

declare(strict_types=1);

namespace Chuck\Database;


interface QueryInterface
{
    public function __construct(DatabaseInterface $db, string $script, Args $args);
    public function one(int $fetchMode): ?array;
    public function all(int $fetchMode): iterable;
    public function run(): bool;
    public function len(): int;
    public function interpolate(): string;
}