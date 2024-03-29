<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Setup;

class C
{
    public static function root(): string
    {
        return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Fixtures';
    }

    public static function tmp(): string
    {
        return sys_get_temp_dir() . DIRECTORY_SEPARATOR;
    }
}
