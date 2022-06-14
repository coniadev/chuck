<?php

declare(strict_types=1);

namespace Chuck\Response;


class JsonResponse extends Response
{
    public function __construct(
        protected mixed $data,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ) {
        parent::__construct(null, $statusCode, $headers);

        $this->header('Content-Type', 'application/json', true);
    }

    public function getBody(): string
    {
        if ($this->data instanceof \Traversable) {
            return json_encode(iterator_to_array($this->data), JSON_UNESCAPED_SLASHES);
        }

        return json_encode($this->data, JSON_UNESCAPED_SLASHES);
    }
}
