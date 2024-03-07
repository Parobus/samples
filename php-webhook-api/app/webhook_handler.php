<?php

namespace WebhookHandler;

class WebhookHandler
{
    public function verifyWebhook()
    {
        $webhookSignatureHeader = 't=1709269756129545591,v1=JbdxsK3vvhQykBYSJrfDLOqE5EVAye6YWLAqOnqdQ6YeKp5fRdChm7Q435S19/tM2HuALYCsUfPR67oJhA6jsg==,alg=sha512';


        $payloadWebhook = '{"payload":{"additionalInformation":"Appropriate amount for the LTV required is displayed","amount":0,"amountMax":0,"case":{"status":"pending","uuid":"QE100919928"},"exclusionReasons":[],"index":{"index":7,"total":53},"lender":{"btl":false,"name":"WestBrom Building Society","notices":[],"primaryLender":null,"reference":"westbrom","resi":true,"type":"first_charge"},"screenshotPdfUrl":"stage\/919928\/westbrom\/tmp\/export_westbrom_919928_8a546f3c646ee5215539a60d13723c669a7f059a16831a49519d5d242a119e31.pdf","status":null},"topic":"case_results"}';
        $data = (array) json_decode($payloadWebhook, true);


        $flattenedData = $this->flattenArray($data);


        $outputArray = [];
        foreach ($flattenedData as $actualKey => $value) {
            $pattern = '/\.\d+\.?\d*$/';
            $key = preg_replace($pattern, '', $actualKey);
            $outputArray[] = $key . '=' . (is_bool($value) ? ($value ? 'true' : 'false') : $value);
        }


        $payload = strtolower(implode(',', $outputArray));


        $secretKey = config('mbt.secret');
        list($timestamp, $signature, $algorithm) = explode(',', $webhookSignatureHeader);
        $signatureFull = implode("=", array_slice(explode("=", $signature), 1));
        list(, $timestamp) = explode('=', $timestamp);
        list(, $signature) = explode('=', $signature);
        list(, $algorithm) = explode('=', $algorithm);




        $verifySignature = $this->verify($timestamp, $signatureFull, $payload, $secretKey, $algorithm);


        dd($verifySignature);
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




    public function verify($timestamp, $signature, $payload, $secret, $algorithm)
    {
        $signedPayload = $timestamp . '.' . $payload;
        $computedSignature = hash_hmac($algorithm, $signedPayload, $secret, true);
        if (base64_encode($computedSignature) !== $signature) {
            return false;
        }
        return true;
    }
}
