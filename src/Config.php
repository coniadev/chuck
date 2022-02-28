<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use \ValueError;

use Chuck\Util\Http;
use Chuck\Util\Path;


class Config implements ConfigInterface
{
    public readonly bool $debug;
    public readonly string $env;

    protected readonly array $config;
    protected readonly array $pathMap;

    public function __construct(protected array $pristine)
    {
        $this->pristine = array_merge(
            require 'defaults.php',
            $pristine,
        );

        $pristineEnv = $pristine['env'] ?? null;
        $this->env = (!empty($pristineEnv) && is_string($pristineEnv)) ? $pristineEnv : '';
        $this->debug = is_bool($pristine['debug'] ?? null) ? $pristine['debug'] : false;
        [$this->config, $this->pathMap] = $this->read($this->pristine);
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

    protected function prepareMainPaths(array $pristine): array
    {
        // The root directory of the project. The setting is mandatory.
        if (isset($pristine['path.root'])) {
            $root = rtrim(Path::realpath($pristine['path.root']), DIRECTORY_SEPARATOR);

            if (!Path::isAbsolute($root)) {
                throw new ValueError('Configuration error: root path must be an absolute path: ' . $root);
            }

            unset($pristine['path.root']);
        } else {
            throw new ValueError('Configuration error: root path not set');
        }

        // Public directory containing the static assets and index.php
        // If it is not set look for a directory named 'public' in path.root
        if (!isset($pristine['path.public'])) {
            $public = $this->preparePath($root, 'public');

            if (!is_dir($public)) {
                throw new ValueError(
                    'Configuration error: public directory is not set and could not be determined'
                );
            }
        } else {
            $public = $this->preparePath($root, $pristine['path.public']);
            unset($pristine['path.public']);
        }

        $paths = [
            'root' => $root,
            'public' => $public,
            'migrations' => [],
            'scripts' => [],
            'sql' => [],
            'templates' => [],
        ];

        // The file where the logger and the error handler write
        // their messages
        $logfile = $pristine['path.logfile'] ?? null;

        if ($logfile) {
            if (!file_exists($logfile)) {
                touch($logfile);
            }

            if (!is_writable($logfile)) {
                throw new ValueError(
                    'Configuration error: logfile is not writable'
                );
            }

            unset($pristine['path.logfile']);
            $paths['logfile'] = $logfile;
        }

        return [$paths, $pristine];
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

    protected function read(array $pristine): array
    {
        [$pathMap, $pristine] = $this->prepareMainPaths($pristine);
        $config = [];
        $root = $pathMap['root'];


        foreach ($pristine as $key => $value) {
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
                    $pathMap['templates'][$subKey] = $this->preparePath($root, $value);
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

    public function debug(): bool
    {
        return $this->debug;
    }

    public function env(): string
    {
        return $this->env;
    }

    public function path(string $key): string
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

        throw new InvalidArgumentException(
            "Path id '$key' is not present in configuration"
        );
    }

    public function pathOrNull(string $key): ?string
    {
        try {
            return $this->path($key);
        } catch (\Exception) {
            return null;
        }
    }

    public function pathsOrEmpty(string $key): array
    {
        try {
            return $this->paths($key);
        } catch (\Exception) {
            return [];
        }
    }

    public function paths(string $key): array
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

        throw new InvalidArgumentException(
            "Paths id '$key' is not present in configuration"
        );
    }

    public function templates(): array
    {
        return  $this->pathMap['templates'];
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
