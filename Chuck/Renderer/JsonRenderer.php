<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\RequestInterface;

class JsonRenderer implements RendererInterface
{
    public function __construct(
        RequestInterface $request,
        $data,
        string $identifier
    ) {
        $this->request = $request;
        $this->data = $data;
    }

    public function render(): string
    {
        // If $context is of type 'object' it should be a Generator
        if (gettype($this->data) === 'object') {
            return json_encode(iterator_to_array($this->data), JSON_UNESCAPED_SLASHES);
        }

        return json_encode($this->data, JSON_UNESCAPED_SLASHES);
    }

    public function headers(): iterable
    {
        return [
            [
                'name' => 'Content-type',
                'value' => 'application/json',
            ], [
                'name' => 'X-CSRF-Token',
                'value' => $this->request->session->csrf->get(),
            ],
        ];
    }
}
