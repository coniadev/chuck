<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use \ValueError;

use Chuck\Util\Http;
use Chuck\Util\Path;
use Chuck\{Response, ResponseInterface};
use Chuck\{Template, TemplateInterface};
use Chuck\{Session, SessionInterface};
use Chuck\Renderer\RendererInterface;


class Config implements ConfigInterface
{
    public readonly bool $debug;
    public readonly string $env;

    protected readonly array $config;
    protected readonly array $pathMap;
    protected array $registryMap;
    protected array $renderers;

    public function __construct(protected array $pristine)
    {
        $this->pristine = array_merge(
            require 'defaults.php',
            $pristine,
        );

        $pristineEnv = $pristine['env'] ?? null;
        $this->env = (!empty($pristineEnv) && is_string($pristineEnv)) ? $pristineEnv : '';
        $this->debug = is_bool($pristine['debug'] ?? null) ? $pristine['debug'] : false;

        $this->registryMap = [
            ResponseInterface::class => Response::class,
            TemplateInterface::class => Template::class,
            SessionInterface::class => Session::class,
        ];

        $this->renderers = [
            'text' => Renderer\TextRenderer::class,
            'json' => Renderer\JsonRenderer::class,
            'template' => Renderer\TemplateRenderer::class,
        ];

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
        if (isset($pristine['path.root'])) {
            $root = rtrim(Path::realpath($pristine['path.root']), DIRECTORY_SEPARATOR);

            if (!Path::isAbsolute($root)) {
                throw new ValueError('Configuration error: root path must be an absolute path: ' . $root);
            }

            unset($pristine['path.root']);
        } else {
            throw new ValueError('Configuration error: root path not set');
        }

        if (!isset($pristine['path.public'])) {
            $public = $this->preparePath($root, 'public');

            if (!is_dir($public)) {
                throw new ValueError(
                    'Configuration error: public directory is not set and could not be determined'
                );
            }
        } else {
            $public = $pristine['path.public'];
            unset($pristine['path.public']);
        }

        return [[
            'root' => $root,
            'public' => $public,
            'migrations' => [],
            'scripts' => [],
            'sql' => [],
            'templates' => [],
        ], $pristine];
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
                    $pathMap[$subKey] = $this->preparePath($root, $value);
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
     * Returns the given $key from the configuration file
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

            throw new InvalidArgumentException("Chuck Error: The configuration key '$key' does not exist");
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
        $value = $this->pathMap[$key];

        if (is_string($value)) {
            return $value;
        }

        throw new InvalidArgumentException('Requested path is not of type string');
    }

    public function paths(string $key): array
    {
        $value = $this->pathMap[$key];

        if (is_array($value)) {
            return $value;
        }

        throw new InvalidArgumentException('Requested paths are not of type array');
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

    public function registry(string $key): string
    {
        return $this->registryMap[$key] ??
            throw new InvalidArgumentException("Undefined registry key \"$key\"");
    }

    public function register(string $interface, string $class): void
    {
        if (!interface_exists($interface)) {
            throw new InvalidArgumentException("Interface does not exist: $interface");
        }

        if (!class_exists($class)) {
            throw new InvalidArgumentException("Class does not exist: $class");
        }

        if (!(is_subclass_of($class, $interface))) {
            throw new InvalidArgumentException("The class does not implement the interface");
        }

        $this->registryMap[$interface] = $class;
    }

    public function registered(string $key): bool
    {
        return array_key_exists($key, $this->registryMap);
    }

    public function addRenderer(string $key, string $class): void
    {
        if (!(is_subclass_of($class, RendererInterface::class))) {
            throw new InvalidArgumentException(
                "The renderer class does not implement " . RendererInterface::class
            );
        }

        $this->renderers[$key] = $class;
    }

    public function renderer(string $key): string
    {
        return $this->renderers[$key] ??
            throw new InvalidArgumentException("Undefined renderer \"$key\"");
    }

    public function __toString(): string
    {
        return print_r($this->config, return: true);
    }
}
