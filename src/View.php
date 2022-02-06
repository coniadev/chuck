<?php

declare(strict_types=1);

namespace Chuck;


abstract class View
{
    public function __construct(
        protected RequestInterface $request,
    ) {
    }

    abstract public function call(): mixed;
}
