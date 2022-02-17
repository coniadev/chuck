<?php

declare(strict_types=1);

namespace Chuck;

interface SessionInterface
{
    public function __construct(RequestInterface $request);
    public function start(): void;
    public function forget(): void;
    public function get(string $key): mixed;
    public function set(string $key, mixed $value): void;
    public function flash(string $type, string $message): void;
    public function hasFlashes(): bool;
    public function popFlash(): array;
    public function regenerate(): void;
    public function setUser(string|int $userId): void;
    public function authenticatedUserId(): mixed;
    public function rememberReturnTo(): void;
    public function returnTo(): string;
    // public function remember(Token $token, int $expire);
    public function forgetRemembered(): void;
    public function getAuthToken(): ?string;
}
