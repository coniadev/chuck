<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use \TypeError;
use \ValueError;
use Chuck\Response\Response;


class TextRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        return $data;
    }

    public function response(mixed $data): Response
    {
        try {
            return (new Response($this->render($data)))->header(
                'Content-Type',
                ($this->args['contentType'] ?? null) ?: 'text/plain',
                true,
            );
        } catch (TypeError) {
            throw new ValueError('Text renderer error: Wrong type [' . gettype($data) . ']');
        }
    }
}
