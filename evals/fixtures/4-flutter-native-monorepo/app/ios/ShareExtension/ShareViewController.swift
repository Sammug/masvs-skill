import Security
import UIKit

final class ShareViewController: UIViewController {
    private let group = "group.com.example.app"

    func sessionToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "session",
            kSecAttrAccessGroup as String: group,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func upload(_ payload: Data) {
        var request = URLRequest(url: URL(string: "http://upload.example.invalid/share")!)
        request.httpMethod = "POST"
        request.setValue("Bearer \(sessionToken() ?? "")", forHTTPHeaderField: "Authorization")
        URLSession.shared.uploadTask(with: request, from: payload).resume()
    }
}
