<?php

declare(strict_types=1);

namespace Chuck\Database;


enum ArgType
{
    case Named;
    case Positional;
}
