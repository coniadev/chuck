<?php

declare(strict_types=1);

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


test('Clean with default extensions', function () {
    $clean = '
        Test
        <div>Test</div>
        <ul><li>Test</li></ul>
                <h1>Test</h1>
        Test';

    expect(Html::clean(MALFORMED))->toBe($clean);
});


test('Clean with block extension', function () {
    $clean = '
        Test
        <aside><div>Test</div></aside>
        Test
        <article>
            <section>
                <h1>Test</h1>
            </section>
        </article>
        Test';

    expect(Html::clean(MALFORMED, ['basic', 'block']))->toBe($clean);
});


test('Clean with headfoot extension', function () {

    $clean = '
        <header>Test</header>
        <div>Test</div>
        Test
                <h1>Test</h1>
        <footer>Test</footer>';

    expect(Html::clean(MALFORMED, ['basic', 'headfoot']))->toBe($clean);
});


test('Clean with nav extension', function () {
    $clean = '
        Test
        <div>Test</div>
        <nav><ul><li>Test</li></ul></nav>
                <h1>Test</h1>
        Test';

    expect(Html::clean(MALFORMED, ['basic', 'list', 'nav']))->toBe($clean);
});
