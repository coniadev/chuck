<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Util\Path;
use Chuck\{Response, ResponseInterface};
use Chuck\{Template, TemplateInterface};
use Chuck\{Session, SessionInterface};
use Chuck\Renderer\RendererInterface;


class Config implements ConfigInterface
{
    protected readonly array $config;
    protected readonly array $paths;
    protected readonly array $memcached;
    protected readonly array $db;

    public function __construct(array $config)
    {
        $defaults = require 'defaults.php';

        $this->paths = [
            'migrations' => [],
            'scripts' => [],
            'sql' => [],
            'templates' => [],
        ];

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

        $this->read(array_merge(
            $defaults,
            $config,
        ));
    }

    protected function read(array $config): void
    {
        $this->config = $config;

        foreach ($config as $key => $value) {
            $segments = explode(trim(strtolower($key)), '.');

            switch ($segments[0]) {
                case 'path':
                    $this->paths[$segments[1]] = Path::realpath($value);
                    break;
                case 'templates':
                    $this->paths['templates'][$segments[1]] = Path::realpath($value);
                    break;
                case 'migrations':
                    $this->paths['migrations'][] = Path::realpath($value);
                    break;
                case 'scripts':
                    $this->paths['scripts'][] = Path::realpath($value);
                    break;
                case 'sql':
                    $this->paths['sql'][] = Path::realpath($value);
                    break;
                case 'db':
                    $this->db[$segments[1]] = $value;
                    break;
            }
        }

        if (!isset($config['path.root'])) {
            throw new \ValueError('Configuration error: root path not set');
        }

        if (!isset($config['path.public'])) {
            $proposedPublic = $config['path.root'] . DIRECTORY_SEPARATOR . 'public';
            if (is_dir($proposedPublic)) {
                $this->path['path']['public'] = $proposedPublic;
            } else {
                throw new \ValueError('Configuration error: public directory is not set and could not be determined');
            }
        }
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
}
