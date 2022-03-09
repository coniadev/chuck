<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use \Throwable;
use \ValueError;

use Chuck\Util\Http;
use Chuck\Util\Path as PathUtil;
use Chuck\Config\{Path, Templates, Log, Database, Connection, Scripts};


class Config implements ConfigInterface
{
    public const DEFAULT = 'default';

    public readonly string $root;
    public readonly bool $debug;
    public readonly string $env;
    public readonly string $app;
    public readonly Path $path;

    protected readonly array $settings;

    public function __construct(array $settings)
    {
        $settings = $this->initDefaults($this->getNested($settings));
        $this->app = $this->getApp($settings);

        $settingsEnv = $settings['env'] ?? null;
        $this->env = (!empty($settingsEnv) && is_string($settingsEnv)) ? $settingsEnv : '';

        // Debug defaults to false to prevent leaking of unwanted information to production
        $this->debug = is_bool($settings['debug'] ?? null) ? $settings['debug'] : false;

        $this->root = $this->getRoot($settings);
        $this->path = new Path(
            $this->root,
            $settings['path'] ?? []
        );
        $this->settings = $settings;
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
                    case 'templates':
                        $nested['templates'][self::DEFAULT] = $value;
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

    protected function getRoot(array $settings): string
    {
        if (isset($settings['path']['root'])) {
            $root = rtrim(PathUtil::realpath($settings['path']['root']), DIRECTORY_SEPARATOR);

            if (!PathUtil::isAbsolute($root)) {
                throw new ValueError('Configuration error: root path must be an absolute path: ' . $root);
            }

            return $root;
        } else {
            throw new ValueError('Configuration error: root path not set');
        }
    }

    protected function getApp(array $settings): string
    {
        try {
            if (preg_match('/^[a-z0-9]{1,32}$/', $settings['app'])) {
                return $settings['app'];
            } else {
                throw new ValueError;
            }
        } catch (Throwable) {
            throw new ValueError(
                "The 'app' setting must exist in the config file. It must " .
                    ' be a nonempty string which consist only of lower case letters ' .
                    'and numbers. Its length must not be longer than 32 characters.'
            );
        }
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

    protected function getDatabaseConfig(): Database
    {
        return new Database(
            $this->root,
            $this->settings['db'] ?? [],
            $this->settings['sql'] ?? [],
            $this->settings['migrations'] ?? [],
        );
    }

    public function db(string $connection = self::DEFAULT, string $sql = self::DEFAULT): Connection
    {
        return $this->getDatabaseConfig()->connection($connection, $sql);
    }

    public function migrations(): array
    {
        return $this->getDatabaseConfig()->migrations();
    }

    public function path(): Path
    {
        return $this->path;
    }

    public function log(): Log
    {
        return new Log($this->root, $this->settings['log'] ?? []);
    }

    public function templates(): array
    {
        return (new Templates(
            $this->root,
            $this->settings['templates'] ?? []
        ))->get();
    }

    public function scripts(): array
    {
        return (new Scripts(
            $this->root,
            $this->settings['scripts'] ?? []
        ))->get();
    }
}
