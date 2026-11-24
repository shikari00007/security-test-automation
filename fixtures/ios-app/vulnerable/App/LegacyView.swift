import UIKit
import WebKit

class LegacyView: UIViewController {
    let legacy = UIWebView()

    func modern() {
        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
    }
}
