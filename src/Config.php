<?php

declare(strict_types=1);

namespace Chuck;

use \Closure;
use \InvalidArgumentException;
use \Throwable;
use \ValueError;
use Psr\Log\LoggerInterface;
use Chuck\Renderer\{
    Renderer,
    JsonRenderer,
    TextRenderer,
};
use Chuck\Util\Path as PathUtil;
use Chuck\Config\{Connection, Scripts};


class Config implements ConfigInterface
{
    public const DEFAULT = 'default';

    protected readonly string $root;
    protected readonly string $public;
    protected readonly bool $debug;
    protected readonly string $env;
    protected readonly string $app;

    protected Closure $loggerCallback;
    protected LoggerInterface $logger;
    protected array $settings;
    /** @var array<string, array{class: class-string<Renderer>, settings: mixed}> */
    protected array $renderers = [];
    /** @var array<string, Connection> */
    protected array $connections = [];

    public function __construct(
        string $app,
        string $root,
        string $public = null,
        bool $debug = false,
        string $env = '',
        array $settings = []
    ) {
        $this->app = $this->getApp($app);
        $this->root = $this->getRoot($root);
        $this->public = $this->getPublic($public);
        $this->debug = $debug;
        $this->env = $env;
        $this->settings = $settings;

        $this->renderers = [
            'text' => ['class' => TextRenderer::class, 'settings' => null],
            'json' => ['class' => JsonRenderer::class, 'settings' => null],
        ];
    }

    protected function getNested(array $flat): array
    {
        $nested = [];

        foreach ($flat as $key => $value) {
            $dotpos = strpos($key, '.');

            if ($dotpos === false) {
                if (isset($nested[$key][self::DEFAULT])) {
                    throw new ValueError(
                        "Configuration error: subkey '" . self::DEFAULT .
                            "' for config key '$key' already exists"
                    );
                }

                switch ($key) {
                    case 'sql':
                        $nested['sql'][self::DEFAULT] = $value;
                        break;
                    case 'migrations':
                        $nested['migrations'][self::DEFAULT] = $value;
                        break;
                    case 'scripts':
                        $nested['scripts'][self::DEFAULT] = $value;
                        break;
                    case 'db':
                        $nested['db'][self::DEFAULT] = $value;
                        break;
                    default:
                        $nested[$key] = $value;
                        break;
                }
                continue;
            }

            $nested[strtok($key, '.')][substr($key, $dotpos + 1)] = $value;
        }

        return $nested;
    }

    protected function getApp(string $app): string
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

    protected function getRoot(string $root): string
    {
        $root = rtrim(PathUtil::realpath($root), DIRECTORY_SEPARATOR);

        if (!PathUtil::isAbsolute($root)) {
            throw new ValueError('Configuration error: root path must be an absolute path: ' . $root);
        }

        return $root;
    }

    protected function preparePublic(string $dir): string
    {
        $dir = PathUtil::realpath($dir);

        if (!PathUtil::isAbsolute($dir)) {
            $dir = $this->root . DIRECTORY_SEPARATOR . $dir;
        }

        if (is_dir($dir)) {
            return $dir;
        }

        throw new ValueError(
            'Configuration error: public directory is not set and could not be determined'
        );
    }

    protected function getPublic(?string $public): string
    {
        if (isset($public)) {
            return $this->preparePublic($public);
        } else {
            return $this->preparePublic('public');
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

    public function root(): string
    {
        return $this->root;
    }

    public function public(): string
    {
        return $this->public;
    }

    public function debug(): bool
    {
        return $this->debug;
    }

    public function env(): string
    {
        return $this->env;
    }

    public function addRenderer(string $name, string $class, mixed $settings = null): void
    {
        if ($class instanceof Renderer) {
            $this->renderers[$name] = ['class' => $class, 'settings' => $settings];
        } else {
            throw new ValueError('A renderer must extend ' . Renderer::class);
        }
    }

    public function renderers(): array
    {
        return $this->renderers;
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
        if (isset($this->loggerCallback)) {
            if (isset($this->logger)) {
                return $this->logger;
            }

            $this->logger = ($this->loggerCallback)();

            return $this->logger;
        }

        return null;
    }

    public function scripts(): array
    {
        return (new Scripts(
            $this->settings['scripts'] ?? [],
        ))->get();
    }
}
