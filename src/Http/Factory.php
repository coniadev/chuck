<?php

declare(strict_types=1);

namespace Conia\Chuck\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

interface Factory
{
    public function request(): ServerRequestInterface;

    public function response(int $code = 200, string $reasonPhrase = ''): ResponseInterface;

    public function stream(mixed $content = ''): StreamInterface;

    public function streamFromFile(string $filename, string $mode = 'r'): StreamInterface;
}
