<?php

declare(strict_types=1);

namespace Chuck;

interface RouteInterface
{
    public function url(array $args): string;
    public function view(): string|\Closure;
    public function name(): string;
    public function args(): array;
    public function method(string ...$args): self;
    public function middleware(callable $middleware): self;
    public function render(string $renderer, mixed ...$args): self;
    public function getRenderer(): ?Renderer\Config;
}
