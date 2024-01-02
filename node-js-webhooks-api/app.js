const express = require('express')
const app = express()
const port = 6000

app.use(express.json())

class WebhookStringPayload {
    static flattenKeyValue([key, value]) {
        if (typeof value === "object" && value !== null) {
            if (Array.isArray(value)) {
                return value.flatMap((element, index) =>
                    WebhookStringPayload.flattenKeyValue([`${key}[${index}]`, element])
                );
            } else {
                return Object.entries(value).flatMap(([subkey, subvalue]) =>
                    WebhookStringPayload.flattenKeyValue([`${key}.${subkey}`, subvalue])
                );
            }
        } else {
            return [`${key}=${WebhookStringPayload.put_value(value)}`];
        }
    }

    static convertToString(map) {
        if (typeof map === "object" && map !== null && !Array.isArray(map)) {
            return Object.entries(map)
                .flatMap((entry) => WebhookStringPayload.flattenKeyValue(entry))
                .sort()
                .join(",");
        } else {
            throw new Error("Input must be a non-null object.");
        }
    }

    static put_value(value) {
        if (value === null) {
            return ''
        }
        return value
    }
}

function verifySignature(data, SIGNATURE, SECRET) {
    const PAYLOAD = WebhookStringPayload.convertToString(data).toLowerCase();
    console.log(PAYLOAD)
    const { createHmac } = require('crypto');

    const VALIDITY_TIME_IN_SECONDS = 5;

    function parse(signature, schema = 'v1') {
        const [timestampString, hashWithVersion, algorithmString] = signature.split(',')
        const timestamp = timestampString.split('=')[1];
        const hash = hashWithVersion.split('=').slice(1).join('='); // in case the hash contains '='
        const algorithm = algorithmString.split('=')[1];

        return { timestamp, hash, algorithm };
    }

    function verify(header, payload, secret, schema = 'v1') {
        const {
            timestamp,
            hash,
            algorithm
        } = parse(header, schema);

        const integerTimestamp = parseInt(timestamp);

        if ((integerTimestamp + VALIDITY_TIME_IN_SECONDS) < Date.now()) {
            return false;
        }

        const hmac = createHmac("sha256", secret);
        hmac.update(`${timestamp}.${payload}`);
        const computedHash = hmac.digest('base64');
        if (computedHash === hash) {
            return true;
        }

        return false;
    }

    // Example signature verification
    return verify(SIGNATURE, PAYLOAD, SECRET)
}

app.use('/', (req, res) => {
    console.log("=== Checking Webhook Signature ===")
    console.log(req.headers['x-webhook-signature'])
    console.log(req.body)
    if (verifySignature(req.body, req.headers['x-webhook-signature'], 'abc123')) {
        console.log('Successfully Verified')
        res.send('Successfully Verified')
    }
    else {
        console.log('Failed to Verify')
        res.send('Failed to Verify')
    }

})

app.listen(port, () => {
    console.log(`Example app listening on http://locallhost:${port}`)
})