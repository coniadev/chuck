<?php

declare(strict_types=1);

namespace Conia\Chuck\Renderer;

use Conia\Chuck\ResponseWrapper;

interface Renderer
{
    public function render(mixed $data, mixed ...$args): string;

    public function response(mixed $data, mixed ...$args): ResponseWrapper;
}
