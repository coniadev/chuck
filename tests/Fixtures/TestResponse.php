<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\ResponseWrapper;
use Psr\Http\Message\ResponseInterface as PsrResponse;

class TestResponse implements ResponseWrapper
{
    public function __construct(protected PsrResponse $psr)
    {
    }

    public function psr(): PsrResponse
    {
        return $this->psr;
    }
}
