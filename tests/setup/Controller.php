<?php

declare(strict_types=1);

namespace Chuck\Tests;


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
}
