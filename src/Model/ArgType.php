<?php

declare(strict_types=1);

namespace Chuck\Model;


enum ArgType
{
    case Named;
    case Positional;
}
