<?php

declare(strict_types=1);

namespace Chuck\Lib\Templates;

use League\Plates\Engine;

use Chuck\RequestInterface;
use Chuck\TemplateInterface;


class PlatesTemplate implements TemplateInterface
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
        $this->defaults = $defaults;

        $this->engine = new Engine();

        foreach ($config->templates() as $key => $dir) {
            $this->engine->addFolder($key, $dir);
        }
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
