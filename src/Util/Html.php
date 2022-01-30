<?php

declare(strict_types=1);

namespace Chuck\Util;

use Chuck\Util\Sanitizer\{BlockExtension, HeadFootExtension, NavExtension};

class Html
{
    public static function clean(string $html, array $extensions = []): string
    {
        $builder = \HtmlSanitizer\SanitizerBuilder::createDefault();
        $builder->registerExtension(new BlockExtension());
        $builder->registerExtension(new HeadFootExtension());
        $builder->registerExtension(new NavExtension());

        if (count($extensions) > 0) {
            $config = ['extensions' => $extensions];
        } else {
            $config = [
                'extensions' => [
                    // a, b, br, blockquote, div, del, em, figcaption,
                    // figure, h1, h2, h3, h4, h5, h6, i, p, q, small,
                    // span, strong, sub, sup
                    'basic',

                    // dd, dl, dt, li, ol, ul
                    'list',

                    //'block',   // section, article, aside
                    //'code',    // pre, code
                    //'details', // allows the insertion of view/hide blocks: details, summary
                    //'extra',   // abbr, caption, hr, rp, rt, ruby
                    //'headfoot',// header, footer
                    //'iframe',  // iframe
                    //'image',   // img
                    //'nav',     // nav
                    //'table',   // table, thead, tbody, tfoot, tr, td, th
                ],
            ];
        }
        $sanitizer = $builder->build($config);

        // also remove empty lines
        return preg_replace(
            "/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/",
            PHP_EOL,
            $sanitizer->sanitize($html)
        );
    }
}
