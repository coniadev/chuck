<?php

declare(strict_types=1);

namespace Chuck;

interface RequestInterface
{
    public function matchdict(string $key, ?string $default = null): ?string;
    public function params(): array;
    public function param(string $key, ?string $default = null): null|string|array;
    public function routeUrl(string $name, array $args = []): string;
    public function staticUrl(string $name, string $path): string;
    public function url();
    public function redirect(string $url, int $code = 302): ResponseInterface;
    public function router(): RouterInterface;
    public function flash(string $type, string $message);
    public function popFlash(): array;
    public function permissions(): ?array;
    public function user(): ?array;
    public function method(): string;
    public function isMethod(string $method): bool;
    public function redirectToRemembered(int $code = 302);
    public function devel(): bool;
    public function isXHR(): bool;
    public function jsonBody(): ?array;
    public function addMethod(string $name, callable $func);
}
