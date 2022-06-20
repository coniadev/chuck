<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use \ErrorException;
use \ValueError;
use Chuck\Response\Response;
use Chuck\Template\Engine;


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

        $request = $this->request;
        $config = $request->config();
        $template = new Engine(
            $this->options,
            defaults: [
                'config' => $config,
                'request' => $request,
                'router' => $request->router(),
                'debug' => $config->debug(),
                'env' => $config->env(),
            ]
        );

        return $template->render($templateName, $context);
    }

    public function response(mixed $data): Response
    {
        return (new Response($this->render($data)))->header(
            'Content-Type',
            ($this->args['contentType'] ?? null) ?: 'text/html',
            true
        );
    }
}
