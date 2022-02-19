<?php

declare(strict_types=1);

namespace Chuck\Tests;

use Chuck\Request;
use Chuck\Response;


class Controller
{
    public function textView(): string
    {
        return 'success';
    }

    public function arrayView(): array
    {
        return ['success' => true];
    }

    public function middlewareView(Request $request): Response
    {
        $response = $request->response;
        $response->setBody($response->getBody() . ' view');
        return $response;
    }
}
