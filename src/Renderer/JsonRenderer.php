<?php

declare(strict_types=1);

namespace Chuck\Renderer;


class JsonRenderer extends Renderer
{
    public function render(): string
    {
        // If $context is of type 'object' it should be a Generator
        if ($this->data instanceof \Traversable) {
            return json_encode(iterator_to_array($this->data), JSON_UNESCAPED_SLASHES);
        }

        return json_encode($this->data, JSON_UNESCAPED_SLASHES);
    }

    public function headers(): iterable
    {
        $headers = [
            [
                'name' => 'Content-Type',
                'value' => 'application/json',
                'replace' => true,
            ]
        ];

        // if (method_exists($this->request, 'session')) {
        // $headers[] = [
        // 'name' => 'X-CSRF-Token',
        // 'value' => $this->request->session()->csrf->get(),
        // 'replace' => true,
        // ];
        // }

        return $headers;
    }
}
