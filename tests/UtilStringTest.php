<?php

declare(strict_types=1);

use Chuck\Util\Strings;


test('String entropy', function () {
    $lower = Strings::entropy('spirit crusher');
    $upper = Strings::entropy('SPIRIT CRUSHER');
    $mixed = Strings::entropy('Spirit Crusher');

    expect($lower)->toBe($upper);
    expect($lower)->toBeLessThan($mixed);
    expect(Strings::entropy('Correct Horse Battery Staple'))->toBeGreaterThan(100);
    expect(Strings::entropy('evil-chuck-666'))->toBeGreaterThan(40);
    expect(Strings::entropy('acegik'))->toBeLessThan(15);
    expect(Strings::entropy('12345'))->toBeLessThan(10);
    expect(Strings::entropy('1'))->toBe(0.0);
});
