<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Throwable;
use Conia\Chuck\Error\ValueError;
use Conia\Chuck\Response\Response;

class TextRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        return (string)$data;
    }

    public function response(mixed $data): Response
    {
        try {
            return (new Response($this->render($data)))->header(
                'Content-Type',
                (string)(($this->args['contentType'] ?? null) ?: 'text/plain'),
                true,
            );
        } catch (Throwable $e) {
            throw new ValueError(
                'Text renderer error: Probably wrong type [' .
                    get_debug_type($data) .
                    "]\n" . $e->getMessage()
            );
        }
    }
}
