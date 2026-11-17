import UIKit

func run(token: String) {
    UserDefaults.standard.set(true, forKey: "onboarded")
    let q = [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    let current = UIPasteboard.general.string
    NSLog("loading")
    NSLog("token refreshed")
}
