<?php

declare(strict_types=1);

namespace Conia\Chuck\Util;

use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;
use Symfony\Component\HtmlSanitizer\HtmlSanitizer;


class Html
{
    public static function clean(
        string $html,
        ?HtmlSanitizerConfig $config = null,
        bool $removeEmptyLines = true,
    ): string {
        $config = $config ?: (new HtmlSanitizerConfig())
            // Allow "safe" elements and attributes. All scripts will be removed
            // as well as other dangerous behaviors like CSS injection
            ->allowSafeElements();
        $sanitizer = new HtmlSanitizer($config);
        $result = $sanitizer->sanitize($html);

        // also remove empty lines
        return $removeEmptyLines ?
            preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", PHP_EOL, $result) :
            $result;
    }
}
