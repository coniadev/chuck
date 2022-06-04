<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use \ErrorException;
use \ValueError;
use Chuck\Body\Body;
use Chuck\Body\Text;


class TextRenderer extends Renderer
{
    public function render(): Body
    {
        try {
            return new Text((string)$this->data);
        } catch (ErrorException) {
            throw new ValueError('Text renderer error: Wrong type [' . gettype($this->data) . ']');
        }
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
