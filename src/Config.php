<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Exception\ValueError;
use Throwable;

/** @psalm-api */
class Config
{
    /**
     * @param array<never, never>|array<string, mixed> -- Stores additional user defined settings
     */
    public function __construct(
        public readonly string $app,
        public readonly bool $debug = false,
        public readonly string $env = '',
        protected array $settings = [],
    ) {
        $this->validateApp($app);
    }

    public function set(string $key, mixed $value): void
    {
        $this->settings[$key] = $value;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->settings);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        if (isset($this->settings[$key])) {
            return $this->settings[$key];
        }

        if (func_num_args() > 1) {
            return $default;
        }

        throw new OutOfBoundsException(
            "The configuration key '{$key}' does not exist"
        );
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

    protected function validateApp(string $app): void
    {
        if (!preg_match('/^[a-zA-Z0-9_$-]{1,64}$/', $app)) {
            throw new ValueError(
                'The app name must be a nonempty string which consist only of lower case ' .
                    'letters and numbers. Its length must not be longer than 32 characters.'
            );
        }
    }
}
