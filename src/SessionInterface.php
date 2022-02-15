<?php

declare(strict_types=1);

namespace Chuck;

interface SessionInterface
{
    public function __construct(RequestInterface $request);
    public function start();
    public function forget();
    public function get($key);
    public function set(string $key, $value);
    public function flash(string $type, string $message);
    public function hasFlashes(): bool;
    public function popFlash(): array;
    public function regenerate();
    public function setUser($userId);
    public function authenticatedUserId();
    public function rememberReturnTo();
    public function returnTo(): string;
    // public function remember(Token $token, int $expire);
    public function forgetRemembered();
    public function getAuthToken(): ?string;
}
