<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Util;


class TemplateRenderer extends Renderer
{
    public function render(): string
    {
        $this->request = $this->request;
        $this->context = $this->data ?? [];

        // Plates needs a double colon, plugin route renderers
        // need to be configured with a single one.
        $this->template = implode('::', explode(':', $this->args[0]));


        if (gettype($this->context) === 'object') {
            $this->context = iterator_to_array($this->context);
        }

        $class = $this->request->config->di('Template');
        $template = new $class($this->request, [
            'request' => $this->request,
            'config' => $this->request->config,
            'devel' => $this->request->devel(),
        ]);
        return $template->render($this->template, $this->context);
    }

    public function headers(): iterable
    {
        if (array_key_exists('contenttype', $this->args)) {
            return [
                [
                    'name' => 'Content-Type',
                    'value' => $this->args['contenttype'],
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
