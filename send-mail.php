<?php
/**
 * Project enquiry form handler for CDB Contracting LLC.
 *
 * Receives the "Project enquiry" form from index.html and delivers it to
 * cdbcontracting.admin@gmail.com by logging in to Gmail over SMTP.
 *
 * Settings (Gmail account and App Password) live in mail-config.php.
 * Upload both files next to index.html on a host that runs PHP.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

function respond($ok, $message, $code = 200)
{
    http_response_code($code);
    echo json_encode(array('ok' => $ok, 'message' => $message));
    exit;
}

$fail_message = 'Sorry, your enquiry could not be sent. Please email info@cdbcontracting.ae directly.';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(false, 'Method not allowed.', 405);
}

$config_file = __DIR__ . '/mail-config.php';
if (!is_file($config_file)) {
    error_log('send-mail.php: mail-config.php is missing.');
    respond(false, $fail_message, 500);
}
$config = require $config_file;

// ----------------------------------------------------------------------
// Spam traps
// ----------------------------------------------------------------------
// A hidden field that real visitors never see or fill in.
if (!empty($_POST['website'])) {
    respond(true, 'Thank you. Your enquiry has been sent.');
}
// Forms submitted faster than 3 seconds after the page loaded.
$started = isset($_POST['started']) ? (int) $_POST['started'] : 0;
if ($started > 0 && (round(microtime(true) * 1000) - $started) < 3000) {
    respond(true, 'Thank you. Your enquiry has been sent.');
}

// ----------------------------------------------------------------------
// Read and check the form
// ----------------------------------------------------------------------
function field($key, $max)
{
    $value = isset($_POST[$key]) ? trim((string) $_POST[$key]) : '';
    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, $max, 'UTF-8');
    }
    return substr($value, 0, $max);
}

// Removes line breaks so nobody can inject extra mail headers.
function one_line($value)
{
    return trim(preg_replace('/[\r\n\t]+/', ' ', $value));
}

$name    = one_line(field('name', 100));
$subject = one_line(field('subject', 140));
$email   = one_line(field('email', 254));
$phone   = one_line(field('phone', 40));
$message = field('message', 1200);

if ($name === '' || $subject === '' || $email === '' || $phone === '' || $message === '') {
    respond(false, 'Please complete every field.', 422);
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    respond(false, 'Please use a valid email address.', 422);
}

// ----------------------------------------------------------------------
// Build the email
// ----------------------------------------------------------------------
$ip   = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
$date = date('d M Y, H:i');

$body  = "New project enquiry from the website\r\n";
$body .= "=====================================\r\n\r\n";
$body .= "Name:    {$name}\r\n";
$body .= "Email:   {$email}\r\n";
$body .= "Phone:   {$phone}\r\n";
$body .= "Subject: {$subject}\r\n\r\n";
$body .= "Message:\r\n" . preg_replace('/\r\n|\r|\n/', "\r\n", $message) . "\r\n\r\n";
$body .= "-------------------------------------\r\n";
$body .= "Sent: {$date} | IP: {$ip}\r\n";

function encode_header($text)
{
    return '=?UTF-8?B?' . base64_encode($text) . '?=';
}

$from_email = $config['username'];
$to_emails  = array_values(array_filter((array) $config['to_email']));
$domain     = substr(strrchr($from_email, '@'), 1);

$headers = array(
    'Date: ' . date('r'),
    'From: ' . encode_header($config['from_name']) . " <{$from_email}>",
    'To: ' . implode(', ', array_map(function ($a) { return "<{$a}>"; }, $to_emails)),
    'Reply-To: ' . encode_header($name) . " <{$email}>",
    'Subject: ' . encode_header('Website enquiry: ' . $subject),
    'Message-ID: <' . bin2hex(random_bytes(12)) . "@{$domain}>",
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
);
$raw_message = implode("\r\n", $headers) . "\r\n\r\n" . chunk_split(base64_encode($body), 76, "\r\n");

// ----------------------------------------------------------------------
// Minimal SMTP client (SSL on 465, or STARTTLS on 587)
// ----------------------------------------------------------------------
class SmtpError extends Exception
{
}

function smtp_read($socket)
{
    $response = '';
    while (($line = fgets($socket, 515)) !== false) {
        $response .= $line;
        // A space after the 3-digit code marks the last line of the reply.
        if (strlen($line) < 4 || $line[3] === ' ') {
            break;
        }
    }
    if ($response === '') {
        throw new SmtpError('No response from SMTP server.');
    }
    return $response;
}

function smtp_cmd($socket, $command, $expect, $log_command = null)
{
    if ($command !== null) {
        fwrite($socket, $command . "\r\n");
    }
    $response = smtp_read($socket);
    $code = (int) substr($response, 0, 3);
    if (!in_array($code, (array) $expect, true)) {
        $shown = $log_command !== null ? $log_command : $command;
        throw new SmtpError("SMTP error after \"{$shown}\": " . trim($response));
    }
    return $response;
}

function smtp_send($config, $from, $to, $raw_message)
{
    $host     = $config['host'];
    $port     = (int) $config['port'];
    $secure   = strtolower($config['secure']);
    $prefix   = $secure === 'ssl' ? 'ssl://' : 'tcp://';
    $context  = stream_context_create(array('ssl' => array(
        'verify_peer'      => true,
        'verify_peer_name' => true,
        'peer_name'        => $host,
    )));

    $socket = @stream_socket_client(
        $prefix . $host . ':' . $port,
        $errno,
        $errstr,
        20,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if (!$socket) {
        throw new SmtpError("Could not connect to {$host}:{$port} ({$errstr}).");
    }
    stream_set_timeout($socket, 20);

    try {
        $helo = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
        smtp_cmd($socket, null, 220);
        smtp_cmd($socket, "EHLO {$helo}", 250);

        if ($secure === 'tls') {
            smtp_cmd($socket, 'STARTTLS', 220);
            if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new SmtpError('Could not start TLS encryption.');
            }
            smtp_cmd($socket, "EHLO {$helo}", 250);
        }

        smtp_cmd($socket, 'AUTH LOGIN', 334);
        smtp_cmd($socket, base64_encode($config['username']), 334, '[username]');
        smtp_cmd($socket, base64_encode($config['password']), 235, '[password]');

        smtp_cmd($socket, "MAIL FROM:<{$from}>", 250);
        foreach ((array) $to as $recipient) {
            smtp_cmd($socket, "RCPT TO:<{$recipient}>", array(250, 251));
        }
        smtp_cmd($socket, 'DATA', 354);

        // Dot-stuffing: lines starting with "." get an extra "."
        $data = preg_replace('/^\./m', '..', $raw_message);
        smtp_cmd($socket, $data . "\r\n.", 250, '[message body]');
        smtp_cmd($socket, 'QUIT', 221);
    } finally {
        fclose($socket);
    }
}

try {
    smtp_send($config, $from_email, $to_emails, $raw_message);
} catch (Exception $e) {
    // The details go to the server's PHP error log, never to the visitor.
    error_log('send-mail.php: ' . $e->getMessage());
    respond(false, $fail_message, 500);
}

respond(true, 'Thank you. Your enquiry has been sent. We will contact you soon.');
