//
//  AES256.swift
//  AES256
//
//  Created by Jiwon Nam on 2020/12/09.
//

import Foundation
import CommonCrypto
import CryptoKit

class AES256 {
    static fileprivate func deriveKeyAndIv(passphrase: String, salt: [UInt8]) -> (key: [UInt8], iv: [UInt8]) {
        let passphrase = Array(passphrase.data(using: .utf8)!)
        var dx: [UInt8] = []
        var di: [UInt8] = []
        for _ in 0 ..< 3 {
            di = md5(bytes: di + passphrase + salt)
            dx += di
        }
        return (key: [UInt8](dx[0...31]), iv: [UInt8](dx[32...47]))
    }
    
    static fileprivate func md5(bytes: [UInt8]) -> [UInt8] {
        // Used by CryptoKit
        let digest = Insecure.MD5.hash(data: bytes)
        return [UInt8](Data(digest))
        // CommonCrypto
//        let length = Int(CC_MD5_DIGEST_LENGTH)
//        let messageData = Data(bytes)
//        var digestData = Data(count: length)
//
//        _ = digestData.withUnsafeMutableBytes { digestBytes -> UInt8 in
//            messageData.withUnsafeBytes { messageBytes -> UInt8 in
//                if let messageBytesBaseAddress = messageBytes.baseAddress, let digestBytesBlindMemory = digestBytes.bindMemory(to: UInt8.self).baseAddress {
//                    let messageLength = CC_LONG(messageData.count)
//                    CC_MD5(messageBytesBaseAddress, messageLength, digestBytesBlindMemory)
//                }
//                return 0
//            }
//        }
//        return [UInt8](digestData)
    }
    
    static fileprivate func crypt(operation: Int, algorithm: Int, options: Int, key: Data,
            initializationVector: Data, dataIn: Data) -> Data? {
        return key.withUnsafeBytes { keyUnsafeRawBufferPointer in
            return dataIn.withUnsafeBytes { dataInUnsafeRawBufferPointer in
                return initializationVector.withUnsafeBytes { ivUnsafeRawBufferPointer in
                    // Give the data out some breathing room for PKCS7's padding.
                    let dataOutSize: Int = dataIn.count + kCCBlockSizeAES128*2
                    let dataOut = UnsafeMutableRawPointer.allocate(byteCount: dataOutSize,
                        alignment: 1)
                    defer { dataOut.deallocate() }
                    var dataOutMoved: Int = 0
                    let status = CCCrypt(CCOperation(operation), CCAlgorithm(algorithm),
                        CCOptions(options),
                        keyUnsafeRawBufferPointer.baseAddress, key.count,
                        ivUnsafeRawBufferPointer.baseAddress,
                        dataInUnsafeRawBufferPointer.baseAddress, dataIn.count,
                        dataOut, dataOutSize, &dataOutMoved)
                    guard status == kCCSuccess else { return nil }
                    return Data(bytes: dataOut, count: dataOutMoved)
                }
            }
        }
    }

    static fileprivate func randomSalt(length: Int) -> [UInt8]? {
        guard let randomData = randomData(length: length) else { return nil }
       return [UInt8](randomData)
    }

    static fileprivate func randomData(length: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: length)
        
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        guard status == kCCSuccess else { return nil }
        return Data(bytes)
    }
}

extension String {
    // MARK: Encrypt and Decrypt String
    
    /// Encrypt AES256 String
    /// - Parameter keyString: Encryption key
    /// - Returns: base64 encoded string
    func encrypt_AES256(keyString: String) -> String? {
        let data = self.data(using: .utf8)!
        guard let salt = AES256.randomSalt(length: 16) else {
            debugPrint("random salt generating error.")
            return nil
        }
        
        let keyAndIv = AES256.deriveKeyAndIv(passphrase: keyString, salt: salt)
        let key = Data(keyAndIv.key)
        let iv = Data(keyAndIv.iv)
        
        guard let cipher = AES256.crypt(operation: kCCEncrypt,
                                        algorithm: kCCAlgorithmAES128,
                                        options: kCCOptionPKCS7Padding,
                                        key: key,
                                        initializationVector: iv,
                                        dataIn: data)
        else {
            debugPrint("AES256 encrypt error")
            return nil
        }

        let cipherArray = salt + [UInt8](cipher)
        let result = Data(bytes: cipherArray, count: cipherArray.count)
        return result.base64EncodedString()
    }
    
    
    /// Decrypt AES256 String
    /// - Parameter keyString: Decryption key string
    /// - Returns: String
    func decrypt_AES256(keyString: String) -> String? {
        
        let data = [UInt8](Data(base64Encoded: self)!)
        let salt = [UInt8](data[0...15])
        let cipher = Data(data[16...])
        let ctx = AES256.deriveKeyAndIv(passphrase: keyString, salt: salt)
        let key = Data(ctx.key)
        let iv = Data(ctx.iv)
        
        guard let cipherArray = AES256.crypt(operation: kCCDecrypt,
                                       algorithm: kCCAlgorithmAES128,
                                       options: kCCOptionPKCS7Padding,
                                       key: key,
                                       initializationVector: iv,
                                       dataIn: cipher) else {
            debugPrint("AES256 decrypt error")
            return nil
        }

        return String(data: cipherArray, encoding: .utf8)
    }
}
