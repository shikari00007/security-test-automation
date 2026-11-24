import Foundation
import Security
import UIKit

// UserDefaults.standard.set(token, forKey: "authToken")  -- commented, ignored
final class Storage {
    func save(token: String, data: Data) {
        UserDefaults.standard.set(token, forKey: "authToken")
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "session",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}
