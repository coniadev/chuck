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
    protected readonly array $templates;
    protected readonly array $migrations;
    protected readonly array $scripts;
    protected readonly array $memcached;
    protected readonly array $db;

    public function __construct(array $config)
    {
        $defaults = require 'defaults.php';

        $this->read(array_merge(
            $defaults,
            $config,
        ));

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
    }

    protected function read(array $config): void
    {
        $this->config = $config;

        foreach ($config as $key => $value) {
            $segments = explode(trim(strtolower($key)), '.');

            switch ($segments[0]) {
                case 'path':
                    $this->paths[$segments[1]] = $value;
                    break;
                case 'templates':
                    $this->templates[$segments[1]] = $value;
                    break;
                case 'db':
                    $this->db[$segments[1]] = $value;
                    break;
                case 'migrations':
                    $this->migrations[] = $value;
                    break;
                case 'scripts':
                    $this->scripts[] = $value;
                    break;
            }
        }

        if (!isset($config['path.root'])) {
            throw new \ValueError('Configuration error: root path not set');
        }

        if (!isset($config['path.public'])) {
            $this->config['path.public'] = $this->config['path.root'] . DIRECTORY_SEPARATOR . 'public';
            $this->path['path']['public'] = $this->config['path.public'];
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
        $path = $this->config['path'][$key];

        if (is_array($path)) {
            return array_map(function ($p) {
                return Path::realpath($p);
            }, $path);
        }

        return Path::realpath($this->config['path'][$key]);
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
