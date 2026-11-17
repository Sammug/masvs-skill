import UIKit

func run(token: String, otp: String) {
    UserDefaults.standard.set(token, forKey: "auth_token")
    UserDefaults.standard["refreshToken"] = token
    let q = [kSecAttrAccessible as String: kSecAttrAccessibleAlways]
    UIPasteboard.general.string = otp
    NSLog("session %@", token)
    NSLog("session \(token)")
    CC_MD5(data, len, &digest)
}
