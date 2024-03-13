<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Log;

class WebhookStringPayload
{
    public static function flattenKeyValue($key, $value)
    {
        $out = new \Symfony\Component\Console\Output\ConsoleOutput();

        if (is_array($value) || is_object($value)) {
            if (is_array($value) && array_keys($value) !== range(0, count($value) - 1)) {
                $out->writeln(json_encode($value));
                $output = [];
                foreach ($value as $subkey => $element) {
                    $output = array_merge($output, self::flattenKeyValue("{$key}.{$subkey}", $element));
                }
                return $output;
            } else {
                $out->writeln(json_encode($value));
                $output = [];
                foreach ($value as $index => $element) {
                    $output = array_merge($output, self::flattenKeyValue("{$key}[$index]", $element));
                }
                return $output;
            }
        } else {
            return ["{$key}=" . self::putValue($value)];
        }
    }

    public static function convertToString($map)
    {
        if (is_array($map) || is_object($map)) {
            $output = [];
            foreach ($map as $key => $value) {
                $output = array_merge($output, self::flattenKeyValue($key, $value));
            }
            sort($output);
            return implode(",", $output);
        } else {
            throw new Exception("Input must be a non-null object.");
        }
    }

    public static function putValue($value)
    {
        if ($value === null) {
            return '';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        return $value;
    }
}

class WebhookHandler
{
    public function verify($timestamp, $signatureFull, $payloadString, $secretKey, $algorithm)
    {

        $integerTimestamp = intval($timestamp);

        if (($integerTimestamp + 200000) < time()) {
            return false;
        }

        $payload = strtolower($payloadString);

        $computedHash = hash_hmac($algorithm, "{$timestamp}.{$payload}", $secretKey, true);

        $computedHashBase64 = base64_encode($computedHash);


        if ($computedHashBase64 === $signatureFull) {
            return true;
        }

        return false;
    }
    public function verifyWebhook($data, $webhookSignatureHeader)
    {
        $out = new \Symfony\Component\Console\Output\ConsoleOutput();
        $out->writeln($webhookSignatureHeader);
        $out->writeln(json_encode($data));

        $stringifier = new WebhookStringPayload();

        $payloadString = $stringifier->convertToString($data);

        $out->writeln($payloadString);


        $secretKey = "abc123";
        list($timestamp, $signature, $algorithm) = explode(',', $webhookSignatureHeader);
        $signatureFull = implode("=", array_slice(explode("=", $signature), 1));
        list(, $timestamp) = explode('=', $timestamp);
        list(, $signature) = explode('=', $signature);
        list(, $algorithm) = explode('=', $algorithm);



        $verifySignature = $this->verify($timestamp, $signatureFull, $payloadString, $secretKey, $algorithm);

        if ($verifySignature === false) {
            $out->writeln("Webhook werify failed");
        } else {
            $out->writeln("Webhook verified");
        }

        return $verifySignature;
    }
    public function flattenArray($array, $prefix = '')
    {
        $result = [];
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $result = array_merge($result, $this->flattenArray($value, $prefix . $key . '.'));
            } else {
                $result[$prefix . $key] = $value;
            }
        }
        return $result;
    }

}


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/
Route::post('/webhook', function (Request $request) {
    $webhookHandler = new WebhookHandler();
    $result = $webhookHandler->verifyWebhook($request->all(), $request->header('x-webhook-signature'));
    return response()->json(['valid' => $result]);
});

