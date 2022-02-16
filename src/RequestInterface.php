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
    public function getResponse(
        ?int $statusCode = null,
        mixed $body = null,
        ?array $headers = [],
        ?string $protocol = null,
        ?string $reasonPhrase = null,
    ): ResponseInterface;
    public function getConfig(): ConfigInterface;
    public function getRouter(): RouterInterface;
    public function method(): string;
    public function isMethod(string $method): bool;
    public function debug(): bool;
    public function env(): string;
    public function isXHR(): bool;
    public function jsonBody(): ?array;
    public function addMethod(string $name, callable $func);
}
