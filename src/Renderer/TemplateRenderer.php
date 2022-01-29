<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\RequestInterface;
use Chuck\Util;

class TemplateRenderer implements RendererInterface
{
    public function __construct(
        RequestInterface $request,
        $data,
        string $identifier
    ) {
        $this->request = $request;
        $this->context = $data ?? [];

        // Plates needs a double colon, plugin route renderers
        // need to be configured with a single one.
        $this->template = implode('::', explode(':', $identifier));
    }

    public function render(): string
    {
        if (gettype($this->context) === 'object') {
            $this->context = iterator_to_array($this->context);
        }
        $class = $this->request->config->di('Template');
        $template = new $class($this->request, [
            'request' => $this->request,
            'config' => $this->request->config,
            'devel' => $this->request->devel(),
            'util' => new Util($this->request),
        ]);
        return $template->render($this->template, $this->context);
    }

    public function headers(): iterable
    {
        return [];
    }
}
