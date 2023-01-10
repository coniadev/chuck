<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Exception\ValueError;
use Psr\Log\LoggerInterface;
use Throwable;

class Config
{
    public const DEFAULT = 'default';

    /** @var null|Closure():LoggerInterface */
    protected ?Closure $loggerCallback = null;
    protected ?LoggerInterface $logger = null;

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
        try {
            return $this->settings[$key];
        } catch (Throwable) {
            if (func_num_args() > 1) {
                return $default;
            }

            throw new OutOfBoundsException(
                "The configuration key '{$key}' does not exist"
            );
        }
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

    /** @param callable():LoggerInterface $callable */
    public function setupLogger(callable $callback): void
    {
        /** @psalm-var Closure():LoggerInterface */
        $this->loggerCallback = Closure::fromCallable($callback);
    }

    public function logger(): ?LoggerInterface
    {
        if ($this->loggerCallback) {
            if ($this->logger) {
                return $this->logger;
            }

            $this->logger = ($this->loggerCallback)();

            return $this->logger;
        }

        return null;
    }

    protected function validateApp(string $app): void
    {
        if (!preg_match('/^[a-z0-9_$-]{1,64}$/', $app)) {
            throw new ValueError(
                'The app name must be a nonempty string which consist only of lower case ' .
                    'letters and numbers. Its length must not be longer than 32 characters.'
            );
        }
    }
}
