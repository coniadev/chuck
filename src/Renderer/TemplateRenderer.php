<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\TemplateInterface;


class TemplateRenderer extends Renderer
{
    protected array $context;
    protected string $template;

    public function render(): string
    {
        $request = $this->request;
        $context = $this->data ?? [];

        // Plates needs a double colon, plugin route renderers
        // need to be configured with a single one.
        $this->template = implode('::', explode(':', $this->args[0]));

        if (gettype($context) === 'object') {
            $this->context = iterator_to_array($context);
        } else {
            $this->context = $context;
        }

        $class = $request->getConfig()->registry(TemplateInterface::class);
        $template = new $class($request);
        return $template->render($this->template, $this->context);
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
