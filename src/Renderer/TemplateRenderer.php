<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use ErrorException;
use ValueError;
use Conia\Chuck\Response\Response;
use Conia\Boiler\Engine;

class TemplateRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        if ($data instanceof \Traversable) {
            $context = iterator_to_array($data);
        } else {
            $context = $data ?? [];
        }

        try {
            $templateName = $this->args[0];
        } catch (ErrorException) {
            throw new ValueError('No template passed to template renderer');
        }

        if (is_string($this->options)) {
            $this->options = [$this->options];
        } else {
            if (!is_array($this->options) || count($this->options) === 0) {
                throw new ValueError('No template dirs given');
            }
        }

        $engine = $this->createEngine($this->options);

        return $engine->render($templateName, $context);
    }

    public function response(mixed $data): Response
    {
        return (new Response($this->render($data)))->header(
            'Content-Type',
            ($this->args['contentType'] ?? null) ?: 'text/html',
            true
        );
    }

    protected function getDefaults(): array
    {
        $request = $this->request;
        $config = $request->config();

        return [
            'config' => $config,
            'request' => $request,
            'router' => $request->router(),
            'debug' => $config->debug(),
            'env' => $config->env(),
        ];
    }

    protected function createEngine(array $options): Engine
    {
        return new Engine($options, defaults: $this->getDefaults());
    }
}
