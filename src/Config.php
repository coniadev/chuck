<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use \Throwable;
use \ValueError;

use Chuck\Util\Http;
use Chuck\Util\Path;
use Chuck\Config\{Root, Templates, Log};


class Config implements ConfigInterface
{
    public readonly bool $debug;
    public readonly string $env;
    public readonly string $appname;

    protected readonly array $config;
    protected readonly array $pathMap;
    protected readonly Templates $templates;


    public function __construct(protected array $settings)
    {
        $root = new Root($settings);
        $this->templates = new Templates($root);
        [$this->config, $this->pathMap] = $this->read($this->settings);
    }

    protected function preparePath(string $root, string $path): string
    {
        $path = Path::realpath($path);

        if (!Path::isAbsolute($path)) {
            $path = $root . DIRECTORY_SEPARATOR . $path;
        }

        if (str_starts_with($path, $root)) {
            return $path;
        }

        throw new ValueError('Configuration error: paths must be inside the root directory: ' . $root);
    }

    protected function prepareMainPaths(array $settings): array
    {
        // The root directory of the project. The setting is mandatory.
        if (isset($settings['path.root'])) {
            $root = rtrim(Path::realpath($settings['path.root']), DIRECTORY_SEPARATOR);

            if (!Path::isAbsolute($root)) {
                throw new ValueError('Configuration error: root path must be an absolute path: ' . $root);
            }

            unset($settings['path.root']);
        } else {
            throw new ValueError('Configuration error: root path not set');
        }

        // Public directory containing the static assets and index.php
        // If it is not set look for a directory named 'public' in path.root
        if (!isset($settings['path.public'])) {
            $public = $this->preparePath($root, 'public');

            if (!is_dir($public)) {
                throw new ValueError(
                    'Configuration error: public directory is not set and could not be determined'
                );
            }
        } else {
            $public = $this->preparePath($root, $settings['path.public']);
            unset($settings['path.public']);
        }

        $paths = [
            'root' => $root,
            'public' => $public,
            'migrations' => [],
            'scripts' => [],
            'sql' => [],
        ];

        // The file where the logger and the error handler write
        // their messages
        $logfile = $settings['path.logfile'] ?? null;

        if ($logfile) {
            if (!file_exists($logfile)) {
                touch($logfile);
            }

            if (!is_writable($logfile)) {
                throw new ValueError(
                    'Configuration error: logfile is not writable'
                );
            }

            unset($settings['path.logfile']);
            $paths['logfile'] = $logfile;
        }

        return [$paths, $settings];
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

    protected function read(array $settings): array
    {
        [$pathMap, $settings] = $this->prepareMainPaths($settings);
        $config = [];
        $root = $pathMap['root'];


        foreach ($settings as $key => $value) {
            [$mainKey, $subKey] = $this->getKeys($key);

            if (!$subKey) {
                $config[$key] = $value;
                continue;
            }

            switch ($mainKey) {
                case 'path':
                    if (is_array($value)) {
                        $pathMap[$subKey] = array_map(
                            function ($p) use ($root) {
                                return $this->preparePath($root, $p);
                            },
                            $value,
                        );
                    } else {
                        $pathMap[$subKey] = $this->preparePath($root, $value);
                    }
                    break;
                case 'templates':
                    $this->templates->add($subKey, $this->preparePath($root, $value));
                    break;
                case 'migrations':
                    $pathMap['migrations'][] = $this->preparePath($root, $value);
                    break;
                case 'scripts':
                    $pathMap['scripts'][] = $this->preparePath($root, $value);
                    break;
                case 'sql':
                    $pathMap['sql'][] = $this->preparePath($root, $value);
                    break;
                default:
                    if (!array_key_exists($mainKey, $config)) {
                        $config[$mainKey] = [];
                    }

                    $config[$mainKey][$subKey] = $value;
            }
        }

        if (!isset($config['origin'])) {
            $config['origin'] = Http::origin();
        }

        if (!isset($config['host'])) {
            $config['host'] = $_SERVER['HTTP_HOST'] ?? 'localhost';
        }

        return [$config, $pathMap];
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
                return $this->config[$mainKey][$subKey];
            } else {
                return $this->config[$key];
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

    protected function app(): string
    {
        static $app;

        if (!isset($app)) {
            try {
                if (preg_match('/^[a-z0-9]]{1,32}$/', $this->settings['app'])) {
                    $app = $this->settings['app'];
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

        return $app;
    }

    public function debug(): bool
    {
        static $debug;

        if (!isset($debug)) {
            // Debug defaults to false to prevent leaking of unwanted information to production
            $debug = is_bool($this->settings['debug'] ?? null) ? $this->settings['debug'] : false;
        }

        return $debug;
    }

    public function env(): string
    {
        static $env;

        if (!isset($env)) {
            // Make shure env is a string
            $settingsEnv = $this->settings['env'] ?? null;
            $env = (!empty($settingsEnv) && is_string($settingsEnv)) ? $settingsEnv : '';
        }

        return $env;
    }

    public function path(string $key, string $default = ''): string
    {
        $value = $this->pathMap[$key] ?? false;

        if ($value && is_string($value)) {
            return $value;
        }

        if ($value && is_array($value)) {
            throw new InvalidArgumentException(
                "Path id '$key' contains a list of paths. Use Config::paths(\$key)"
            );
        }

        if (func_num_args() > 1) {
            return $default;
        }

        throw new InvalidArgumentException(
            "Path id '$key' is not present in configuration"
        );
    }

    public function paths(string $key, array $default = []): array
    {
        $value = $this->pathMap[$key] ?? false;

        if ($value && is_array($value)) {
            return $value;
        }

        if ($value && is_string($value)) {
            throw new InvalidArgumentException(
                "Paths id '$key' contains a single path. Use Config::path(\$key)"
            );
        }

        if (func_num_args() > 1) {
            return $default;
        }

        throw new InvalidArgumentException(
            "Paths id '$key' is not present in configuration"
        );
    }

    public function templates(): Templates
    {
        return  $this->templates;
    }

    public function migrations(): array
    {
        return  $this->pathMap['migrations'];
    }

    public function sql(): array
    {
        return  $this->pathMap['sql'];
    }

    public function scripts(): array
    {
        return  $this->pathMap['scripts'];
    }
}
