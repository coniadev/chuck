<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Registry\Registry;

interface ViewAttributeInterface
{
    public function injectRegistry(Registry $registry): void;
}
