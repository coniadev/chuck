<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use \ErrorException;
use \ValueError;
use Chuck\Response\Response;
use Chuck\Template\Engine;


class TemplateRenderer extends Renderer
{
    public function response(): Response
    {
        if ($this->data instanceof \Traversable) {
            $context = iterator_to_array($this->data);
        } else {
            $context = $this->data ?? [];
        }

        try {
            $templateName = $this->args[0];
        } catch (ErrorException) {
            throw new ValueError('No template passed to template renderer');
        }

        if (is_string($this->settings)) {
            $this->settings = [$this->settings];
        } else {
            if (!is_array($this->settings) || count($this->settings) === 0) {
                throw new ValueError('No template dirs given');
            }
        }

        $request = $this->request;
        $config = $request->config();
        $template = new Engine(
            $this->settings,
            defaults: [
                'config' => $config,
                'request' => $request,
                'router' => $request->router(),
                'debug' => $config->debug(),
                'env' => $config->env(),
            ]
        );

        return (new Response($template->render($templateName, $context)))->header(
            'Content-Type',
            ($this->args['contentType'] ?? null) ?: 'text/html',
            true
        );
    }
}
