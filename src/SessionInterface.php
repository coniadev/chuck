<?php

declare(strict_types=1);

namespace Chuck;

interface SessionInterface
{
    public function start(): void;
    public function forget(): void;
    public function get(string $key): mixed;
    public function set(string $key, mixed $value): void;
    public function has(string $key): bool;
    public function unset(string $key): void;
    public function regenerate(): void;
    public function flash(string $message, string $queue): void;
    public function hasFlashes(?string $queue): bool;
    public function popFlashes(?string $queue): array;
    public function rememberRequestUri(): void;
    public function getRememberedUri(): string;
}
