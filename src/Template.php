<?php

declare(strict_types=1);

namespace Chuck;

use League\Plates\Engine;

class Template implements TemplateInterface
{
    protected RequestInterface $request;
    protected array $defaults;
    protected string $path;
    protected Engine $engine;

    public function __construct(
        RequestInterface $request,
        array $defaults = [],
    ) {
        $this->request = $request;
        $config = $request->config;
        $this->path = $path ?: $config->path('templates');
        $this->defaults = $defaults;

        $this->engine = new Engine($this->path);

        // TODO: add additional folders
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
