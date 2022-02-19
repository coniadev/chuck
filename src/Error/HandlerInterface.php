<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


interface HandlerInterface
{
    public function addRequest(RequestInterface $request): void;
    public function setup(): void;
}
