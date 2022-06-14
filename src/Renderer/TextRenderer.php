<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use \ErrorException;
use \ValueError;
use Chuck\Response\Response;


class TextRenderer extends Renderer
{
    public function response(): Response
    {
        try {
            return (new Response((string)$this->data))->header(
                'Content-Type',
                ($this->args['contentType'] ?? null) ?: 'text/plain',
                true,
            );
        } catch (ErrorException) {
            throw new ValueError('Text renderer error: Wrong type [' . gettype($this->data) . ']');
        }
    }
}
