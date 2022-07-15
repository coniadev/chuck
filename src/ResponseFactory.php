<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Response\{
    ResponseInterface,
    JsonResponse,
    FileResponse,
    Response,
};

class ResponseFactory
{
    public function html(
        ?string $body = null,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ): ResponseInterface {
        $response = new Response($body, $statusCode, $headers);
        $response->header('Content-Type', 'text/html');

        return $response;
    }

    public function text(
        ?string $body = null,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ): ResponseInterface {
        $response = new Response($body, $statusCode, $headers);
        $response->header('Content-Type', 'text/plain');

        return $response;
    }

    public function file(
        string $file,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
        int $chunkSize = 2 << 20, // 2 MB
        bool $throwNotFound = true, // 2 MB
    ): FileResponse {
        return new FileResponse($file, $statusCode, $headers, $chunkSize, $throwNotFound);
    }

    public function json(
        mixed $data,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ): JsonResponse {
        return new JsonResponse($data, $statusCode, $headers);
    }
}
