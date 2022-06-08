<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;
use Chuck\Body\Json;


class JsonRenderer extends Renderer
{
    public function render(): Body
    {
        return new Json($this->data);
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
