<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Request;
use Conia\Chuck\ResponseWrapper;

interface Middleware
{
    public function __invoke(
        Request $request,
        callable $next
    ): ResponseWrapper;
}
