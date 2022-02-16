<?php

declare(strict_types=1);

namespace Chuck;

use \ValueError;
use Chuck\Util\Path;
use Chuck\{Response, ResponseInterface};
use Chuck\{Template, TemplateInterface};
use Chuck\{Session, SessionInterface};
use Chuck\Renderer\RendererInterface;


class Config implements ConfigInterface
{
    protected readonly array $config;
    protected readonly array $paths;
    protected readonly array $registry;
    protected readonly array $renderers;

    public function __construct(protected array $pristine)
    {
        $this->pristine = array_merge(
            require 'defaults.php',
            $pristine,
        );


        $this->registry = [
            ResponseInterface::class => Response::class,
            TemplateInterface::class => Template::class,
            SessionInterface::class => Session::class,
        ];

        $this->renderers = [
            'string' => Renderer\StringRenderer::class,
            'json' => Renderer\JsonRenderer::class,
            'template' => Renderer\TemplateRenderer::class,
        ];

        [$this->config, $this->paths] = $this->read($this->pristine);
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
                throw new ValueError('Configuration error: public directory is not set and could not be determined');
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

    protected function read(array $pristine): array
    {
        [$paths, $pristine] = $this->prepareMainPaths($pristine);
        $config = [];
        $root = $paths['root'];

        foreach ($pristine as $key => $value) {
            $segments = explode('.', trim($key));

            if (count($segments) === 1) {
                $config[$key] = $value;
                continue;
            }

            // if the key contains more than one '.' merge the remainder
            // e. g. if $key = 'chuck.rick.chris', after the following operation
            // $mainKey will be 'chuck' and $subKey 'rick.chris'
            $mainKey = $segments[0];
            $subKey = implode('.', array_slice($segments, 1));

            switch ($mainKey) {
                case 'path':
                    $paths[$subKey] = $this->preparePath($root, $value);
                    break;
                case 'templates':
                    $paths['templates'][$subKey] = $this->preparePath($root, $value);
                    break;
                case 'migrations':
                    $paths['migrations'][] = $this->preparePath($root, $value);
                    break;
                case 'scripts':
                    $paths['scripts'][] = $this->preparePath($root, $value);
                    break;
                case 'sql':
                    $paths['sql'][] = $this->preparePath($root, $value);
                    break;
                default:
                    if (!array_key_exists($mainKey, $config)) {
                        $config[$mainKey] = [];
                    }

                    $config[$mainKey][$subKey] = $value;
            }
        }

        return [$config, $paths];
    }

    public function get(string $key, $default = null)
    {
        if (func_num_args() > 1) {
            return $this->config[$key] ?? $default;
        }

        if (!array_key_exists($key, $this->config)) {
            throw new \InvalidArgumentException("Chuck Error: The configuration key '$key' does not exist");
        }

        return $this->config[$key];
    }

    public function path(string $key): string|array
    {
        return  $this->paths[$key];
    }

    public function registry(string $key): string
    {
        return $this->registry[$key] ??
            throw new \InvalidArgumentException("Undefined registry key \"$key\"");
    }

    public function register(string $interface, string $class): void
    {
        if (!($class instanceof $interface)) {
            throw new \InvalidArgumentException("The class does not implement the interface");
        }

        $this->registry[$interface] = $class;
    }

    public function addRenderer(string $key, string $class): void
    {
        if (!($class instanceof RendererInterface)) {
            throw new \InvalidArgumentException("The renderer class does not implement " . RendererInterface::class);
        }

        $this->renderers[$key] = $class;
    }

    public function renderer(string $key): string
    {
        return $this->renderers[$key] ??
            throw new \InvalidArgumentException("Undefined renderer \"$key\"");
    }

    public function __toString(): string
    {
        return print_r($this->config, return: true);
    }
}
