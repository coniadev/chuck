<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use \ValueError;
use Chuck\Body\Body;
use Chuck\Body\Text;
use Chuck\RequestInterface;


class TextRenderer extends Renderer
{
    public function __construct(
        RequestInterface $request,
        mixed $data,
        array $args,
    ) {
        if (!is_string($data)) {
            throw new ValueError('Text renderer error: Wrong type [' . gettype($data) . ']');
        }

        parent::__construct($request, $data, $args);
    }

    public function render(): Body
    {
        return new Text((string)$this->data);
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
