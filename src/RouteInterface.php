<?php

declare(strict_types=1);

namespace Chuck;

interface RouteInterface
{
    public function url(array $args): string;
    public function view(): string|callable;
    public function name(): string;
    public function args(): array;
    public function method(string ...$args): self;
    public function middleware(string|object ...$middleware): self;
    public function middlewares(): array;
    public function render(string $renderer, mixed ...$args): self;
    public function controller(string $controller): void;
    public function getRenderer(): ?Renderer\Config;
    public function prefix(string $name, string $prefix): self;
}
