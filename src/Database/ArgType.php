<?php

declare(strict_types=1);

namespace Conia\Chuck\Database;


enum ArgType
{
    case Named;
    case Positional;
}
