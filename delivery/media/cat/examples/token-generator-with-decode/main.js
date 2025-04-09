import { logger } from 'log';
import { CWTGenerator, CWTUtil, CWTValidator } from './cwt.js';
import { AlgoLabelMap, CatURILabelMap, ClaimsLabelMap, HeaderLabelMap, MatchTypeLabelMap, CAT, CatRLabelMap } from './cat.js';
import { TextDecoder, TextEncoder, base16, base64url } from 'encoding';
import { crypto } from 'crypto';
import { createResponse } from 'create-response';

const hs256KeyHex = 'e72edda6a49ee291a779796e994377c53087edf74d6e6a01af2ce59b5a98e0a1';

const cat = new CAT({
    isCoseCborTagAdded: true,
    isCWTTagAdded: true
});

const ClaimsLabelMapR = Object.fromEntries(Object.entries(ClaimsLabelMap).map(([k, v]) => [v, k]));
const CatURILabelMapR = Object.fromEntries(Object.entries(CatURILabelMap).map(([k, v]) => [v, k]));
const MatchTypeLabelMapR = Object.fromEntries(Object.entries(MatchTypeLabelMap).map(([k, v]) => [v, k]));

export async function responseProvider (request) {
    if (request.path === '/token' && request.method === 'POST') {
        try {
            let body = await request.json();
            logger.log('D: body: %s', JSON.stringify(body));

            let catu = body['catu'];
            if (catu) {
                const catuMap = translateJsonToMap(catu, [CatURILabelMap, MatchTypeLabelMap], 0);
                body['catu'] = catuMap;
            }

            let cath = body['cath'];
            if (cath) {
                const cathMap = translateJsonToMap(cath, [{}, MatchTypeLabelMap], 0);
                body['cath'] = cathMap;
            }

            const payload = CWTUtil.claimsTranslate(body, ClaimsLabelMap);
            const isWellFormedPayload = cat.isCATWellFormed(payload);

            if (isWellFormedPayload.status) {
                const protectedHeader = new Map();
                protectedHeader.set(HeaderLabelMap.alg, AlgoLabelMap.HS256);
                const unprotectedHeaders = new Map();
                unprotectedHeaders.set(HeaderLabelMap.kid, new TextEncoder().encode("akamai_key_hs256"));

                const header = { p: protectedHeader, u: unprotectedHeaders };
                const sKey = await crypto.subtle.importKey(
                    'raw',
                    base16.decode(hs256KeyHex, 'Uint8Array').buffer,
                    { name: 'HMAC', hash: 'SHA-256' },
                    false,
                    ['sign', 'verify']
                );

                const signer = { key: sKey };
                const cwtTokenBuf = await CWTGenerator.mac(payload, signer, header, {}, { isCoseCborTagAdded: true, isCWTTagAdded: true });
                const catToken = base64url.encode(new Uint8Array(cwtTokenBuf));
                return createResponse(200, { 'content-type': 'text/plain' }, catToken);
            } else {
                return createResponse(400, {}, isWellFormedPayload.errMsg);
            }
        } catch (err) {
            return createResponse(400, {}, err.message);
        }
    }

    // New /decode endpoint to decode a catToken
    if (request.path === '/decode' && request.method === 'POST') {
        try {
            let body = await request.json();
            let token = body.token;
            logger.log('D: decode catToken');
            if (!token) {
                return createResponse(400, {}, "Missing 'token' in request body.");
            }

            // Decode base64url token
            const tokenBuf = base64url.decode(token);
            // extract payload
            const decodedToken = cat.decode(tokenBuf);
            const payload = decodedToken.payload;
            logger.log('D: payload', payload);
            const result = translateMapToJson(payload, [ClaimsLabelMapR, CatURILabelMapR, MatchTypeLabelMapR]);
            logger.log('D:result',JSON.stringify(result, null, 2));
            return createResponse(200, { 'content-type': 'application/json' }, JSON.stringify(result));
        } catch (err) {
            return createResponse(400, {}, `Decoding error: ${err.message}`);
        }
    }
}

function translateJsonToMap(payload, labelMaps, i) {
    const result = new Map();
    if (payload instanceof Map) {
        payload = Object.fromEntries(payload);
    }
    for (const param in payload) {
        let value = payload[param];
        if (isJSONObject(value)) {
            value = translateJsonToMap(value, labelMaps, i + 1);
        }
        const key = labelMaps[i][param] !== undefined ? labelMaps[i][param] : param;
        result.set(key, value);
    }
    return result;
}

function isJSONObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function translateMapToJson(payload, labelMaps, depth = 0) {
    const result = {};

    // Convert top-level Map to an array for iteration
    if (payload instanceof Map) {
        payload = Array.from(payload.entries());
    }

    for (const [key, value] of payload) {
        let newValue = value;

        // Recursively process nested maps
        if (value instanceof Map) {
            newValue = translateMapToJson(value, labelMaps, depth + 1);
        }

        // Use the correct label map for this depth
        const labelMap = labelMaps[depth];
        let mappedKey = labelMap[key] !== undefined ? labelMap[key] : key;
        result[mappedKey] = newValue;
    }
    return result;
}
