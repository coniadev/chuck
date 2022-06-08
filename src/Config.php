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
use Chuck\Util\Http;
use Chuck\Util\Path as PathUtil;
use Chuck\Config\{Database, Connection, Path, Scripts};


class Config implements ConfigInterface
{
    public const DEFAULT = 'default';

    public readonly string $root;
    public readonly bool $debug;
    public readonly string $env;
    public readonly string $app;

    protected Closure $loggerCallback;
    protected LoggerInterface $logger;
    protected array $settings;
    /** @var array<string, array{class: class-string<Renderer>, settings: mixed}> */
    protected array $renderers = [];
    /** @var array<string, Connection> */
    protected array $connections = [];
    protected readonly Path $path;

    public function __construct(
        array $settings,
        string $app,
        string $root,
        string $public = null,
        bool $debug = false,
        string $env = ''
    ) {
        $settings = $this->initDefaults($this->getNested($settings));
        $this->app = $this->getApp($app);
        $this->root = $this->getRoot($root);
        $this->public = $this->getPublic($public);
        $this->debug = $debug;
        $this->env = $env;
        $this->path = new Path($this->root);

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

    protected function initDefaults(array $settings): array
    {
        if (!isset($settings['origin'])) {
            $settings['origin'] = Http::origin();
        }

        if (!isset($settings['host'])) {
            $settings['host'] = $_SERVER['HTTP_HOST'] ?? 'localhost';
        }

        return $settings;
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

    public function addPath(string $key, string $value): void
    {
        $this->path->add($key, $value);
    }

    public function path(): Path
    {
        return $this->path;
    }

    protected function getKeys(string $key): array
    {
        $segments = explode('.', trim($key));

        if (count($segments) === 1) {
            return [$key, null];
        }

        // if the key contains more than one '.' merge the remainder
        // e. g. if $key = 'chuck.rick.chris', after the following operation
        // $mainKey will be 'chuck' and $subKey 'rick.chris'
        $mainKey = $segments[0];
        $subKey = implode('.', array_slice($segments, 1));

        return [$mainKey, $subKey];
    }


    public function has(string $key): bool
    {
        [$mainKey, $subKey] = $this->getKeys($key);

        if ($subKey) {
            return !empty($this->settings[$mainKey][$subKey]);
        } else {
            return !empty($this->settings[$key]);
        }
    }

    /**
     * Returns the given $key from the configuration
     *
     * Also handles the dotted config file format, e. g. 'db.dsn'
     */
    public function get(string $key, mixed $default = null): mixed
    {
        [$mainKey, $subKey] = $this->getKeys($key);

        try {
            if ($subKey) {
                return $this->settings[$mainKey][$subKey];
            } else {

                return $this->settings[$key];
            }
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
            $this->root,
            $this->settings['scripts'] ?? [],
            $this->debug,
        ))->get();
    }
}
