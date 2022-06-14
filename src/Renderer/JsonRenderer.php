<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Response\JsonResponse;


class JsonRenderer extends Renderer
{
    public function response(): JsonResponse
    {
        return new JsonResponse($this->data);
    }
}
