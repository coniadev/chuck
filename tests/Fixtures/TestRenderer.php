<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use Chuck\Response\Response;
use Chuck\Renderer\Renderer;


class TestRenderer extends Renderer
{
    public function response(): Response
    {
        return new Response('');
    }
}
