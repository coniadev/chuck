<?php

declare(strict_types=1);

use Conia\Chuck\Logger;

beforeEach(function () {
    // capture output of error_log calls in a temporary file
    // to prevent it printed to the console.
    $this->default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);
    $tmpfile = tmpfile();
    $this->logfile = stream_get_meta_data($tmpfile)['uri'];
});


afterEach(function () {
    // Restore default error_log
    ini_set('error_log', $this->default);
});


test('Logger to file', function () {
    $logger = new Logger(logfile: $this->logfile);

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->notice("James");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->critical("Chris");
    $logger->alert("Kelly");
    $logger->emergency("Terry");

    $output = file_get_contents($this->logfile);

    expect($output)->toContain('] DEBUG: Scott');
    expect($output)->toContain('] INFO: Steve');
    expect($output)->toContain('] NOTICE: James');
    expect($output)->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] CRITICAL: Chris');
    expect($output)->toContain('] ALERT: Kelly');
    expect($output)->toContain('] EMERGENCY: Terry');
});


test('Logger to php sapi', function () {
    $logger = new Logger(logfile: $this->logfile);

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->alert("Kelly");

    $output = file_get_contents($this->logfile);

    expect($output)->toContain('] DEBUG: Scott');
    expect($output)->toContain('] INFO: Steve');
    expect($output)->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] ALERT: Kelly');
});


test('Logger with higher debug level', function () {
    $logger = new Logger(Logger::ERROR, $this->logfile);

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->notice("James");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->critical("Chris");
    $logger->alert("Kelly");
    $logger->emergency("Terry");

    $output = file_get_contents($this->logfile);

    expect($output)->not->toContain('] DEBUG: Scott');
    expect($output)->not->toContain('] INFO: Steve');
    expect($output)->not->toContain('] NOTICE: James');
    expect($output)->not->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] CRITICAL: Chris');
    expect($output)->toContain('] ALERT: Kelly');
    expect($output)->toContain('] EMERGENCY: Terry');
});


test('Logger with wrong log level', function () {
    $logger = new Logger(Logger::ERROR, $this->logfile);
    $logger->log(1313, 'never logged');
})->throws(InvalidArgumentException::class, 'Unknown log level');


test('Message interpolation', function () {
    $logger = new Logger(logfile: $this->logfile);

    try {
        throw new Exception('The test exception');
    } catch (Exception $e) {
        $logger->warning(
            'String: {string}, Integer: {integer} ' .
                'DateTime: {datetime}, Array: {array}' .
                'Float: {float}, Object: {object} ' .
                'Other: {other}, Null: {null}',
            [
                'string' => 'Scream Bloody Gore',
                'integer' => 13,
                'float' => 73.23,
                'datetime' => new DateTime('1987-05-25T13:31:23'),
                'array' => [13, 23, 71],
                'object' => new stdClass(),
                'other' => stream_context_create(),
                'null' => null,
                'exception' => $e,
            ]
        );
    }

    $output = file_get_contents($this->logfile);

    expect($output)->toContain('String: Scream Bloody Gore');
    expect($output)->toContain('Integer: 13');
    expect($output)->toContain('Float: 73.23');
    expect($output)->toContain('DateTime: 1987-05-25 13:31:23');
    expect($output)->toContain('Array: [Array [13,23,71]]');
    expect($output)->toContain('Object: [Instance of stdClass]');
    expect($output)->toContain('Other: [resource (stream-context)]');
    expect($output)->toContain('Null: [null]');
    expect($output)->toContain('Exception Message: The test exception');
});
