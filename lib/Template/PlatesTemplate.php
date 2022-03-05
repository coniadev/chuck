<?php

declare(strict_types=1);

namespace Chuck\Lib\Templates;

use League\Plates\Engine;

use Chuck\Template\AbstractTemplate;


class PlatesTemplate implements AbstractTemplate
{
    protected array $defaults;
    protected string $path;
    protected Engine $engine;

    public function __construct(array $dirs, array $defaults = [],)
    {
        $this->defaults = $defaults;

        $this->engine = new Engine();

        foreach ($dirs as $key => $dir) {
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
