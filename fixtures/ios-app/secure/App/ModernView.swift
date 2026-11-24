import UIKit
import WebKit

class ModernView: UIViewController {
    let web = WKWebView()

    func configure() {
        let config = WKWebViewConfiguration()
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
    }
}
