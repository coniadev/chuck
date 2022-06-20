<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Response\JsonResponse;
use Chuck\Util\Json;


class JsonRenderer extends Renderer
{
    public function render(mixed $data): string
    {
        return Json::encode($data);
    }

    public function response(mixed $data): JsonResponse
    {
        return new JsonResponse($data);
    }
}
