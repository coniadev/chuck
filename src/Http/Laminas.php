<?php

declare(strict_types=1);

namespace Conia\Chuck\Http;

use Conia\Chuck\Exception\RuntimeException;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

class Laminas extends AbstractFactory
{
    public function __construct()
    {
        try {
            $this->responseFactory = new ResponseFactory();
            $this->streamFactory = new StreamFactory();
            // @codeCoverageIgnoreStart
        } catch (Throwable) {
            throw new RuntimeException('Install nyholm/psr7-server');
            // @codeCoverageIgnoreEnd
        }
    }

    public function request(): ServerRequestInterface
    {
        return ServerRequestFactory::fromGlobals();
    }
}
