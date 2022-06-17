<?php

declare(strict_types=1);

namespace Chuck\Response;


class JsonResponse extends Response
{
    public function __construct(
        mixed $data,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ) {
        $flags = JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

        if ($data instanceof \Traversable) {
            $body = json_encode(iterator_to_array($data), $flags);
        } else {
            $body = json_encode($data, $flags);
        }

        parent::__construct($body, $statusCode, $headers);

        $this->header('Content-Type', 'application/json', true);
    }
}
