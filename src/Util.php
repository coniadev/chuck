<?php

declare(strict_types=1);

namespace Chuck;

class Util
{

    public function __construct(RequestInterface $request = null)
    {
        $this->request = $request;
    }
}
