//
//  main.swift
//  AES256
//
//  Created by Jiwon Nam on 2021/04/12.
//
import Foundation

let N = 5000
let origin = "ffffsdfdsfasfasdfdsafdsfasfasfaff"
let key = "key"
let encrypted = origin.encrypt_AES256(keyString: key)
let decrypted = encrypted?.decrypt_AES256(keyString: key)
debugPrint("Simple Visible Test")
debugPrint("Origin: \(origin)")
debugPrint("Key: \(key)")
debugPrint("Encrypted: \(encrypted ?? "invalid")")
debugPrint("Decrypted: \(decrypted ?? "invalid")")
assert(origin == decrypted)
func randomString(length: Int) -> String {
  let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
  return String((0..<length).map { _ in letters.randomElement()! })
}
var completedCount: Int = 0
var successCount: Int = 0
var failureCont: Int = 0
let start = CFAbsoluteTimeGetCurrent()
for i in 0 ..< N {
    let rand = randomString(length: i)
    let key = randomString(length: N % 10)
    
    let encrypted = rand.encrypt_AES256(keyString: key)
    let decrypted = encrypted?.decrypt_AES256(keyString: key)
    
    if rand == decrypted {
        successCount += 1
    }
    else {
        failureCont += 1
    }
    completedCount += 1
}
let diff = CFAbsoluteTimeGetCurrent() - start

debugPrint("Test Completed.")
debugPrint("TotalCount Completion: \(completedCount)")
debugPrint("Success: \(successCount)")
debugPrint("Failure: \(failureCont)")
debugPrint("Time: \(diff) sec")
