<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

class TestConfig
{
    /**
     * @param array<never, never>|array<string, mixed> -- Stores additional user defined settings
     */
    public function __construct(
        public readonly string $app,
        public readonly bool $debug = false,
        public readonly string $env = '',
    ) {
    }

    public function app(): string
    {
        return $this->app;
    }

    public function debug(): bool
    {
        return $this->debug;
    }

    public function env(): string
    {
        return $this->env;
    }
}
