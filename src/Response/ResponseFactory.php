<?php

declare(strict_types=1);

namespace Chuck\Response;


class ResponseFactory implements ResponseFactoryInterface
{
    public function make(
        ?string $body = null,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ): ResponseInterface {
        return new Response($body, $statusCode, $headers);
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
