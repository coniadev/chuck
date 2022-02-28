<?php

declare(strict_types=1);

namespace Chuck\Tests\Setup;

class C
{
    const DS = DIRECTORY_SEPARATOR;

    public static function root(): string
    {
        return  dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Fixtures';
    }
}
