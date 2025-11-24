import Foundation
import secp256k1


struct CKSecp256k1 {
    /*
     + (NSData *)generatePublicKeyWithPrivateKey:(NSData *)privateKeyData compression:(BOOL)isCompression
     {
         secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

         const unsigned char *prvKey = (const unsigned char *)privateKeyData.bytes;
         secp256k1_pubkey pKey;

         int result = secp256k1_ec_pubkey_create(context, &pKey, prvKey);
         if (result != 1) {
             return nil;
         }

         int size = isCompression ? 33 : 65;
         unsigned char *pubkey = malloc(size);

         size_t s = size;

         result = secp256k1_ec_pubkey_serialize(context, pubkey, &s, &pKey, isCompression ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
         if (result != 1) {
             return nil;
         }

         secp256k1_context_destroy(context);

         NSMutableData *data = [NSMutableData dataWithBytes:pubkey length:size];
         free(pubkey);
         return data;
     }
     */
    static let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY))
    
    static func generatePublicKey(withPrivateKey privateKeyData: Data,
                                  compression isCompression: Bool) -> Data? {

        guard let context = context else { return nil }

        // --- 1. Prepare private key bytes ---
        var privateKey = [UInt8](privateKeyData)
        guard privateKey.count == 32 else { return nil }

        // --- 2. Create secp256k1_pubkey ---
        var pubkey = secp256k1_pubkey()

        let createResult = secp256k1_ec_pubkey_create(context, &pubkey, &privateKey)
        guard createResult == 1 else {
            return nil // invalid private key
        }

        // --- 3. Prepare serialization buffer ---
        var outputLength = isCompression ? 33 : 65
        var output = Data(repeating: 0, count: outputLength)

        let flags = UInt32(isCompression ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)

        // --- 4. Serialize public key ---
        let serializeResult = output.withUnsafeMutableBytes { outPtr -> Int32 in
            let outBytes = outPtr.bindMemory(to: UInt8.self).baseAddress!

            return secp256k1_ec_pubkey_serialize(
                context,
                outBytes,
                &outputLength,
                &pubkey,
                flags
            )
        }

        guard serializeResult == 1 else {
            return nil
        }

        return output
    }


    /*
     + (NSData *)compactSignData:(NSData *)msgData withPrivateKey:(NSData *)privateKeyData
     {
         secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

         const unsigned char *prvKey = (const unsigned char *)privateKeyData.bytes;
         const unsigned char *msg = (const unsigned char *)msgData.bytes;

         unsigned char *siga = malloc(64);
         secp256k1_ecdsa_signature sig;
         int result = secp256k1_ecdsa_sign(context, &sig, msg, prvKey, NULL, NULL);

         result = secp256k1_ecdsa_signature_serialize_compact(context, siga, &sig);

         if (result != 1) {
             return nil;
         }

         secp256k1_context_destroy(context);

         NSMutableData *data = [NSMutableData dataWithBytes:siga length:64];
         free(siga);
         return data;
     }
     */
    static func compactSignData(msgData: Data, withPrivateKey privateKeyData: Data) -> Data? {

        guard let context = context else { return nil }

        // Must be 32-bytes message hash and 32-byte private key
        var msg = [UInt8](msgData)
        var privateKey = [UInt8](privateKeyData)
        guard msg.count == 32, privateKey.count == 32 else { return nil }

        // 1. Create signature struct
        var signature = secp256k1_ecdsa_signature()

        // 2. Sign message
        let signResult = secp256k1_ecdsa_sign(
            context,
            &signature,
            &msg,
            &privateKey,
            nil,
            nil
        )

        guard signResult == 1 else {
            return nil
        }

        // 3. Serialize to compact (64 bytes)
        var compactSig = Data(repeating: 0, count: 64)

        let serializeResult = compactSig.withUnsafeMutableBytes { buf -> Int32 in
            let sigPtr = buf.bindMemory(to: UInt8.self).baseAddress!
            return secp256k1_ecdsa_signature_serialize_compact(
                context,
                sigPtr,
                &signature
            )
        }

        guard serializeResult == 1 else {
            return nil
        }

        return compactSig
    }

    /*
      + (NSInteger)verifySignedData:(NSData *)sigData withMessageData:(NSData *)msgData usePublickKey:(NSData *)pubKeyData
     {
         secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

         const unsigned char *sig = (const unsigned char *)sigData.bytes;
         const unsigned char *msg = (const unsigned char *)msgData.bytes;

         const unsigned char *pubKey = (const unsigned char *)pubKeyData.bytes;

         secp256k1_pubkey pKey;
         int pubResult = secp256k1_ec_pubkey_parse(context, &pKey, pubKey, pubKeyData.length);
         if (pubResult != 1) return -3;

         secp256k1_ecdsa_signature sig_ecdsa;
         int sigResult = secp256k1_ecdsa_signature_parse_compact(context, &sig_ecdsa, sig);
         if (sigResult != 1) return -4;

         int result = secp256k1_ecdsa_verify(context, &sig_ecdsa, msg, &pKey);

         secp256k1_context_destroy(context);
         return result;
     }*/
    static func verifySignedData(
        sigData: Data,
        withMessageData msgData: Data,
        usePublickKey pubKeyData: Data
    ) -> Int32 {

        guard let context = context else { return -1 }

        // Must be compact ECDSA signature (64 bytes)
        var sigBytes = [UInt8](sigData)
        var msgBytes = [UInt8](msgData)
        var pubBytes = [UInt8](pubKeyData)

        // 1. Parse pubkey
        var publicKey = secp256k1_pubkey()
        let pubResult = secp256k1_ec_pubkey_parse(
            context,
            &publicKey,
            &pubBytes,
            pubKeyData.count
        )

        if pubResult != 1 { return -3 }

        // 2. Parse compact signature
        var signature = secp256k1_ecdsa_signature()
        let sigResult = secp256k1_ecdsa_signature_parse_compact(
            context,
            &signature,
            &sigBytes
        )

        if sigResult != 1 { return -4 }

        // 3. Verify signature
        let verifyResult = secp256k1_ecdsa_verify(
            context,
            &signature,
            &msgBytes,
            &publicKey
        )

        return verifyResult  // 1 = valid, 0 = invalid
    }
}
