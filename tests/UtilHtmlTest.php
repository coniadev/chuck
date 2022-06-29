<?php

declare(strict_types=1);

use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;
use Chuck\Util\Html;

const MALFORMED = '
        <header>Test</header>
        <aside><div>Test</div></aside>
        <iframe src="example.com"></iframe>
        <nav><ul><li>Test</li></ul></nav>
        <article>
            <script>console.log("hans");</script>
            <section>
                <h1 onclick="console.log("hans");">Test</h1>
            </section>
        </article>
        <footer>Test</footer>';


test('Clean with config', function () {
    $clean = '
        <header>Test</header>
        <aside><div>Test</div></aside>
        <nav><ul><li>Test</li></ul></nav>
        <article>
            <section>
                <h1>Test</h1>
            </section>
        </article>
        <footer>Test</footer>';

    expect(Html::clean(MALFORMED))->toBe($clean);
});


test('Clean with block extension', function () {
    $config = (new HtmlSanitizerConfig())
        ->allowSafeElements()
        ->blockElement('header')
        ->blockElement('footer')
        ->blockElement('section');
    $clean = '
        Test
        <aside><div>Test</div></aside>
        <nav><ul><li>Test</li></ul></nav>
        <article>
                <h1>Test</h1>
        </article>
        Test';

    expect(Html::clean(MALFORMED, $config))->toBe($clean);
});
