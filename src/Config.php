<?php

declare(strict_types=1);

namespace Conia\Chuck;

use \Closure;
use \InvalidArgumentException;
use \Throwable;
use \ValueError;
use Psr\Log\LoggerInterface;
use Conia\Chuck\Renderer\{
    Renderer,
    JsonRenderer,
    TextRenderer,
    RendererInterface,
};
use Conia\Chuck\Config\{Connection, Scripts};


class Config implements ConfigInterface
{
    public const DEFAULT = 'default';

    protected readonly bool $debug;
    protected readonly string $env;
    protected readonly string $app;

    protected ?Closure $loggerCallback = null;
    protected ?LoggerInterface $logger = null;
    /** @var array<string, array{class: class-string<Renderer>, options: mixed}> */
    protected array $renderers = [];
    /** @var array<string, Connection> */
    protected array $connections = [];
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected readonly Scripts $scripts;

    /**
     * Stores additional user defined settings
     *
     * @var array<string, mixed>
     */
    protected array $settings;


    public function __construct(
        string $app,
        bool $debug = false,
        string $env = '',
        array $settings = []
    ) {
        $this->app = $this->validateApp($app);
        $this->debug = $debug;
        $this->env = $env;
        $this->settings = $settings;

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

            throw new InvalidArgumentException(
                "Chuck Error: The configuration key '$key' does not exist"
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

    public function renderer(RequestInterface $request, string $type, mixed ...$args): RendererInterface
    {
        $class = $this->renderers[$type]['class'];
        $options = $this->renderers[$type]['options'];

        return new $class($request, $args, $options);
    }


    public function addConnection(Connection $conn, string $name = self::DEFAULT): void
    {
        if (!isset($this->connections[$name])) {
            $this->connections[$name] = $conn;
        } else {
            throw new ValueError("A connection with the name '$name' already exists");
        }
    }

    public function connection(string $name = self::DEFAULT): Connection
    {
        return $this->connections[$name];
    }

    public function setupLogger(Closure $callback): void
    {
        $this->loggerCallback = $callback;
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

    public function scripts(): Scripts
    {
        /**
         * @psalm-suppress RedundantPropertyInitializationCheck
         *
         * See docs/contributing.md
         */
        if (!isset($this->scripts)) {
            /** @psalm-suppress InaccessibleProperty */
            $this->scripts = new Scripts();
        }

        return $this->scripts;
    }
}
