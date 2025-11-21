import Foundation
import P256K

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
    static func generatePublicKey(withPrivateKey privateKeyData: Data, compression isCompression: Bool) -> Data? {
        do {
            // Create private key from raw 32-byte data
            let privateKey = try P256K.Signing.PrivateKey(dataRepresentation: privateKeyData)
            
            // Get public key
            let publicKey = privateKey.publicKey
            
            // Return the desired representation
            if isCompression {
                return publicKey.dataRepresentation    // 33 bytes
            } else {
                return publicKey.uncompressedRepresentation  // 65 bytes
            }
            
        } catch {
            print("Error generating secp256k1/solana public key: \(error)")
            return nil
        }
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
        do {
            // Create secp256k1 private key
            let privateKey = try P256K.Signing.PrivateKey(dataRepresentation: privateKeyData)

            // Sign message
            let signature = try privateKey.signature(for: msgData)

            // Return 64-byte compact signature (R||S)
            return signature.dataRepresentation

        } catch {
            print("P256K signing error:", error)
            return nil
        }
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
        do {
            // Detect public key format based on length
            let keyFormat: P256K.Format
            switch pubKeyData.count {
            case 33:
                keyFormat = .compressed
            case 65:
                keyFormat = .uncompressed
            default:
                return -3 // invalid public key format
            }

            // 1. Parse the public key
            let publicKey = try P256K.Signing.PublicKey(
                dataRepresentation: pubKeyData,
                format: keyFormat
            )

            // 2. Parse the compact signature (64 bytes: r||s)
            let signature = try P256K.Signing.ECDSASignature(
                dataRepresentation: sigData
            )

            // 3. Perform verification
            let isValid = publicKey.isValidSignature(signature, for: msgData)

            return isValid ? 1 : 0

        } catch {
            // Match your old behavior:
            // -3 = pubkey parse error
            // -4 = signature parse error

            let errorString = "\(error)"

            if errorString.contains("public key") {
                return -3
            }
            if errorString.contains("signature") {
                return -4
            }

            return -5 // Generic parse error fallback
        }
    }
}
