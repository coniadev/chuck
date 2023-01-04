<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Throwable;
use Psr\Log\LoggerInterface;
use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Exception\ValueError;
use Conia\Chuck\Renderer\{
    Renderer,
    JsonRenderer,
    TextRenderer,
    RendererInterface,
};

class Config implements ConfigInterface
{
    public const DEFAULT = 'default';

    public readonly bool $debug;
    public readonly string $env;
    public readonly string $app;

    /** @var null|Closure():LoggerInterface */
    protected ?Closure $loggerCallback = null;
    protected ?LoggerInterface $logger = null;
    /** @var array<string, array{class: class-string<Renderer>, options: mixed}> */
    protected array $renderers = [];



    /**
     * @param array<never, never>|array<string, mixed> -- Stores additional user defined settings
     */
    public function __construct(
        string $app,
        bool $debug = false,
        string $env = '',
        protected array $settings = [],
    ) {
        $this->app = $this->validateApp($app);
        $this->debug = $debug;
        $this->env = $env;

        $this->renderers = [
            'text' => ['class' => TextRenderer::class, 'options' => null],
            'json' => ['class' => JsonRenderer::class, 'options' => null],
        ];
    }

    protected function validateApp(string $app): string
    {
        if (preg_match('/^[a-z0-9]{1,32}$/', $app)) {
            return $app;
        } else {
            throw new ValueError(
                'The app name must be a nonempty string which consist only of lower case ' .
                    'letters and numbers. Its length must not be longer than 32 characters.'
            );
        }
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
                "The configuration key '$key' does not exist"
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

    /** @param class-string<Renderer> $class */
    public function addRenderer(string $name, string $class, mixed $options = null): void
    {
        if (is_subclass_of($class, Renderer::class)) {
            $this->renderers[$name] = ['class' => $class, 'options' => $options];
        } else {
            throw new ValueError('A renderer must extend ' . Renderer::class);
        }
    }

    public function renderer(Request $request, string $type, mixed ...$args): RendererInterface
    {
        $class = $this->renderers[$type]['class'];
        /** @psalm-suppress MixedAssignment -- options are mixed values by nature */
        $options = $this->renderers[$type]['options'];

        return new $class($request, $args, $options);
    }

    /** @param callable():LoggerInterface $callable */
    public function setupLogger(callable $callback): void
    {
        /** @var Closure():LoggerInterface */
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
}
