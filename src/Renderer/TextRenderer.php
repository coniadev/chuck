<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;
use Chuck\Body\Text;


class TextRenderer extends Renderer
{
    public function render(): string
    {
        return (string)$this->data;
    }

    public function body(): Body
    {
        return new Text($this->render());
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
