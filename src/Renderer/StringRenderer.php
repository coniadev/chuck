<?php

declare(strict_types=1);

namespace Chuck\Renderer;


class StringRenderer extends Renderer
{
    public function render(): string
    {
        return (string)$this->data;
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
                'value' => 'text/plain',
                'replace' => true,
            ],
        ];
    }
}
