<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use \ErrorException;
use \ValueError;
use Chuck\Body\Body;
use Chuck\Body\Text;
use Chuck\Template\Engine;


class TemplateRenderer extends Renderer
{
    public function render(): Body
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

        if (!is_array($this->settings) || count($this->settings) === 0) {
            throw new ValueError('No template dirs given');
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
        return new Text($template->render($templateName, $context));
    }

    public function headers(): iterable
    {
        if (array_key_exists('contentType', $this->args)) {
            return [
                [
                    'name' => 'Content-Type',
                    'value' => $this->args['contentType'],
                    'replace' => true,
                ],
            ];
        }

        return [
            [
                'name' => 'Content-Type',
                'value' => 'text/html',
                'replace' => true,
            ],
        ];
    }
}
