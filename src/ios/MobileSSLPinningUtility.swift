import Foundation
import Security

@objc(MobileSSLPinningUtility) class MobileSSLPinningUtility : CDVPlugin, URLSessionDelegate {

  //private variables
  let opQueue = OperationQueue()
  var response: URLResponse?
  var session:URLSession?
  var time:DispatchTime! {
    return DispatchTime.now() + 1.0
  }

  //this struct is used to provide identity and trust mechanism for SSL connection
  public struct IdentityAndTrust {
    public var identityRef: SecIdentity
    public var trust: SecTrust
    public var certArray: NSArray
  }


 //this function will validate if a certificate is installed within the app file structure or in the keychain of the device
 @objc(hascertificate:)
 func hascertificate(command: CDVInvokedUrlCommand) {
    //init plugin result
    var response: Dictionary = [ "url" : "https://maximo.mosaicco.com", "status" : false ] as [String : Any]
    var pluginResult = CDVPluginResult(
        status: CDVCommandStatus_OK,
        messageAs: response
    )

    print("Checking for certificate")
    //check for the existence of the p12 certificate
    if let certPath: URL = Bundle.main.url(forResource: "maxmobfirst", withExtension: "p12"),
         let localCertData = try? Data(contentsOf: certPath)
    {
        print("Found certificate. Setting true on callback")
        response = [ "url" : "https://maximo.mosaicco.com", "status" : true ]
        //set the plugin result with OK
        pluginResult = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAs: response
        )
     }

     //send the callback object back
     print("Sending back certificate check response")
     self.commandDelegate!.send(
       pluginResult,
       callbackId: command.callbackId
     )
 }

    //this function will validate if a certificate is installed within the app file structure or in the keychain of the device
    @objc(authenticate:)
    func authenticate(command: CDVInvokedUrlCommand) {
        print("Connecting to Maximo");
        initMaximoGatewayConnection(command: command)
    }


  @objc(echo:)
  func echo(command: CDVInvokedUrlCommand) {
    var pluginResult = CDVPluginResult(
      status: CDVCommandStatus_ERROR
    )

    let msg = command.arguments[0] as? String ?? ""

    if msg.characters.count > 0 {
      let toastController: UIAlertController =
        UIAlertController(
          title: "",
          message: msg,
          preferredStyle: .alert
        )

      self.viewController?.present(
        toastController,
        animated: true,
        completion: nil
      )

      DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
        toastController.dismiss(
            animated: true,
            completion: nil
        )
      }

      pluginResult = CDVPluginResult(
        status: CDVCommandStatus_OK,
        messageAs: msg
      )
    }

    self.commandDelegate!.send(
      pluginResult,
      callbackId: command.callbackId
    )
  }

    //this function will perform the http connection
    func initMaximoGatewayConnection(command: CDVInvokedUrlCommand) {
        print("Initiating Maximo Connection")

        //clear cache
        self.opQueue.isSuspended = true
        let sessionConfiguration = URLSessionConfiguration.default;
        sessionConfiguration.urlCache = nil

        //init session
        self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

        //fire off the request
        let url = URL(string: "https://maximo.mosaicco.com")
        let request = URLRequest(url: url!)
        let task = session?.dataTask(with: request, completionHandler: { (data, response, error) in
            let result = NSString(data: data!, encoding: String.Encoding.ascii.rawValue)
            let urlResponse = response as? HTTPURLResponse;
            print("result: \(result)")
            print("response: \(response)")
            print("error: \(error)")
            print("Sending back Cordova callback with HTML stream");
            //init plugin result
            var response: Dictionary = [ "html" : result, "status" : true, "headers" : urlResponse?.allHeaderFields ] as [String : Any]
            var pluginResult = CDVPluginResult(
                status: CDVCommandStatus_OK,
                messageAs: response
            )
            self.commandDelegate!.send(
                pluginResult,
                callbackId: command.callbackId
            )
        })
        task?.resume()


        //init connection queue after a minute
        DispatchQueue.main.asyncAfter(deadline: self.time, execute: {[weak self] in
            print("Opening the queue")
            self?.opQueue.isSuspended = false
        })

    }

    //this function will extract a passed certificate identity
    private func extractIdentity(certData: NSData, certPassword: String) -> IdentityAndTrust {
        //local variables
        var identityAndTrust: IdentityAndTrust!
        var securityError:OSStatus = errSecSuccess
        var items: CFArray?

        //init cert options object
        let certOptions: Dictionary = [kSecImportExportPassphrase as String: certPassword];

        //extract the certificates
        securityError = SecPKCS12Import(certData, certOptions as CFDictionary, &items);

        //check for an error on the certificates
        if(securityError == errSecSuccess) {
            print("Certificate success. Checking for certificate collection.")

            //extracting cert items
            let certItems:CFArray = items as CFArray!;
            let certItemsArray:Array = certItems as Array
            let dict: AnyObject? = certItemsArray.first;

            //check if an array of certificates exists
            if let certEntry:Dictionary = dict as? Dictionary<String, AnyObject> {
                print("Found collection of certificates. Populating Identity and Trust object")
                //extract identity
                let identityPointer:AnyObject? = certEntry["identity"]
                let secIdentityRef:SecIdentity = identityPointer as! SecIdentity

                //extract trust
                let trustPointer:AnyObject? = certEntry["trust"]
                let trustRef:SecTrust = trustPointer as! SecTrust

                //extract chain
                var certRef: SecCertificate?
                SecIdentityCopyCertificate(secIdentityRef, &certRef)
                let certArray: NSMutableArray = NSMutableArray();
                certArray.add(certRef as SecCertificate!)

                identityAndTrust = IdentityAndTrust(identityRef: secIdentityRef, trust: trustRef, certArray: certArray);
                print("identity and trust mechanism populated")
            }
            else {

            }
        }
        else {
            print("Certificate error. Please check password")
            identityAndTrust = nil
        }
        return identityAndTrust;
    }

    //this override will init when the url session starts
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        print("URLSession callback initiated. Getting certificate")
        if let certPath: URL = Bundle.main.url(forResource: "maxmobfirst", withExtension: "p12"),
            let localCertData = try? Data(contentsOf: certPath)
        {
            //init identity or trust
            let identityAndTrust:IdentityAndTrust = extractIdentity(certData: localCertData as NSData, certPassword: "Mos@ic123$")

            //init URL Credential object and complete
            let urlCredential: URLCredential = URLCredential(identity: identityAndTrust.identityRef, certificates:identityAndTrust.certArray as [AnyObject], persistence: URLCredential.Persistence.forSession)

            print("Checking the challenge handler \(challenge.protectionSpace.authenticationMethod)")
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate || challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
                print("This connection requires a certificate. Adding local cert and trust store")
                completionHandler(URLSession.AuthChallengeDisposition.useCredential, urlCredential)
            }
            else {
                print("Something else happened")
            }
            return
        }
        else {
            print("Certificate not found")
        }
        challenge.sender?.cancel(challenge)
        completionHandler(URLSession.AuthChallengeDisposition.rejectProtectionSpace, nil)
    }
}
