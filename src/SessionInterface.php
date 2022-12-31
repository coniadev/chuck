<?php

declare(strict_types=1);

namespace Conia\Chuck;

interface SessionInterface
{
    public function start(): void;
    public function forget(): void;
    /** @param non-empty-string $key */
    public function get(string $key): mixed;
    /** @param non-empty-string $key */
    public function set(string $key, mixed $value): void;
    /** @param non-empty-string $key */
    public function has(string $key): bool;
    /** @param non-empty-string $key */
    public function unset(string $key): void;
    public function regenerate(): void;
    public function flash(string $message, string $queue): void;
    public function hasFlashes(?string $queue): bool;
    public function popFlashes(?string $queue): array;
    public function rememberRequestUri(): void;
    public function getRememberedUri(): string;
}
