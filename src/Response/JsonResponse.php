<?php

declare(strict_types=1);

namespace Conia\Chuck\Response;

use Conia\Chuck\Util\Json;

class JsonResponse extends Response
{
    public function __construct(
        mixed $data,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ) {
        parent::__construct(Json::encode($data), $statusCode, $headers);

        $this->header('Content-Type', 'application/json', true);
    }
}
