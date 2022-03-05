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
    public readonly bool $debug;
    public readonly string $env;
    public readonly string $app;
    public readonly Path $path;

    protected readonly Database $database;
    protected readonly Templates $templates;
    protected readonly Scripts $scripts;
    protected readonly Log $log;

    protected readonly array $settings;

    public function __construct(array $settings)
    {
        $settings = $this->getNested($settings);
        $this->settings = $this->read($settings);
    }

    protected function getNested(array $flat): array
    {
        $nested = [
            'port' => 1983,
        ];

        foreach ($flat as $key => $value) {
            $dotpos = strpos($key, '.');

            if ($dotpos === false) {
                if (isset($nested[$key]['default'])) {
                    throw new ValueError(
                        "Configuration error: subkey 'default' for config key '$key' already exists"
                    );
                }

                switch ($key) {
                    case 'sql':
                        $nested['sql']['default'] = $value;
                        break;
                    case 'migrations':
                        $nested['migrations']['default'] = $value;
                        break;
                    case 'templates':
                        $nested['templates']['default'] = $value;
                        break;
                    case 'scripts':
                        $nested['scripts']['default'] = $value;
                        break;
                    case 'db':
                        $nested['db']['default'] = $value;
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

    protected function read(array $settings): array
    {
        if (isset($settings['path']['root'])) {
            $root = rtrim(PathUtil::realpath($settings['path']['root']), DIRECTORY_SEPARATOR);

            if (!PathUtil::isAbsolute($root)) {
                throw new ValueError('Configuration error: root path must be an absolute path: ' . $root);
            }
        } else {
            throw new ValueError('Configuration error: root path not set');
        }

        if (!isset($settings['origin'])) {
            $settings['origin'] = Http::origin();
        }

        if (!isset($settings['host'])) {
            $settings['host'] = $_SERVER['HTTP_HOST'] ?? 'localhost';
        }

        $this->database = new Database($root);

        foreach ($settings as $key => $value) {
            switch ($key) {
                case 'path':
                    $this->path = new Path($root, $value);
                    break;
                case 'log':
                    $this->log = new Log($root, $value);
                    break;
                case 'templates':
                    $this->templates = new Templates($root, $value);
                    break;
                case 'scripts':
                    $this->scripts = new Scripts($root, $value);
                    break;
                case 'sql':
                    $this->database->setSql($value);
                    break;
                case 'db':
                    $this->database->setConnections($value);
                    break;
                case 'migrations':
                    $this->database->setMigrations($value);
                    break;
            }
        }

        return $settings;
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
        } catch (\ErrorException) {
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
        if (!isset($this->app)) {
            try {
                if (preg_match('/^[a-z0-9]{1,32}$/', $this->settings['app'])) {
                    $this->app = $this->settings['app'];
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

        return $this->app;
    }

    public function debug(): bool
    {
        if (!isset($this->debug)) {
            // Debug defaults to false to prevent leaking of unwanted information to production
            $this->debug = is_bool($this->settings['debug'] ?? null) ? $this->settings['debug'] : false;
        }

        return $this->debug;
    }

    public function env(): string
    {
        if (!isset($this->env)) {
            // Make shure env is a string
            $settingsEnv = $this->settings['env'] ?? null;
            $this->env = (!empty($settingsEnv) && is_string($settingsEnv)) ? $settingsEnv : '';
        }

        return $this->env;
    }

    public function db(string $connection, string $sql): Connection
    {
        return $this->database->connection($connection, $sql);
    }

    public function migrations(): array
    {
        return $this->database->migrations();
    }

    public function path(): Path
    {
        return $this->path;
    }

    public function log(): Log
    {
        if (!isset($this->log)) {
            $this->log = new Log($this->path->root, []);
        }

        return $this->log;
    }

    public function templates(): array
    {
        return $this->templates->get();
    }

    public function scripts(): array
    {
        if (!isset($this->scripts)) {
            $this->scripts = new Scripts($this->path->root, []);
        }

        return $this->scripts->get();
    }
}
