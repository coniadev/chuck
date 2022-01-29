<?php

declare(strict_types=1);

namespace Chuck;

use League\Plates\Engine;
use Chuck\Plugin;

class Template implements TemplateInterface
{
    protected RequestInterface $request;
    protected array $defaults;
    protected string $path;
    protected Engine $engine;

    public function __construct(
        RequestInterface $request,
        array $defaults = [],
        ?string $path = null
    ) {
        $this->request = $request;
        $config = $request->config;
        $this->path = $path ?: $config->path('templates');
        $this->defaults = $defaults;

        $this->engine = new Engine($this->path);
        $this->engine->addFolder('theme', $this->getThemePath($config));

        foreach (Plugin::templateDirs($request->config, $request) as $dir) {
            $segments = explode(':', $dir);
            $this->engine->addFolder($segments[0], $segments[1]);
        }
    }

    protected function getThemePath(ConfigInterface $config): string
    {
        return $config->path('root') .
            DIRECTORY_SEPARATOR .
            'www' .
            DIRECTORY_SEPARATOR .
            'theme' .
            DIRECTORY_SEPARATOR .
            'templates';
    }

    public function render(string $template, $context = []): string
    {
        $this->engine->addData($this->defaults);
        return $this->engine->render($template, $context);
    }

    public function exists(string $template): bool
    {
        return $this->engine->exists($template);
    }
}
