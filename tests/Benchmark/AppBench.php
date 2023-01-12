<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Benchmark;

use Conia\Chuck\App;
use Conia\Chuck\Config;

class AppBench
{
    /**
     * @Revs(10000)
     */
    public function benchAppInit()
    {
        $app = App::create(new Config('chuck'));
    }
}
