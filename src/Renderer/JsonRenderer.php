<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Response\JsonResponse;
use Chuck\Util\Json;


class JsonRenderer extends Renderer
{
    public function render(): string
    {
        return Json::encode($this->data);
    }

    public function response(): JsonResponse
    {
        return new JsonResponse($this->data);
    }
}
