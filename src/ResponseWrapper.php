<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Psr\Http\Message\ResponseInterface as PsrResponse;

interface ResponseWrapper
{
    public function psr(): PsrResponse;
}
