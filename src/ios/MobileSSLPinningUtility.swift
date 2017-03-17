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
    var rUrl: String = "";
    var rRequest: String = "";
    var rFolder: String = "";
    var rFile: String = "";
    var rPassword: String = "";
    var rHostName: String = "";
    var rAuthorization: String = "";

    //this struct is used to provide identity and trust mechanism for SSL connection
    public struct IdentityAndTrust {
        public var identityRef: SecIdentity
        public var trust: SecTrust
        public var certArray: NSArray
    }

    //this function will perform the GET request
    @objc(GetRequest:)
    func GetRequest(command: CDVInvokedUrlCommand) {

        print("Initiating Get Connection")

        //assign all variables
        rUrl = command.argument(at: 0) as! String
        rRequest = command.argument(at: 1) as! String
        //rFolder = command.argument(at: 2) as! String
        rFile = "*myglobaldatacom" //command.argument(at: 3) as! String
        //rPassword = command.argument(at: 4) as! String
        //rHostName = command.argument(at: 5) as! String
        rAuthorization = command.argument(at: 6) as! String
        var rAuthorizationDictionary = convertToDictionary(text: rAuthorization)!

        //clear cache
        self.opQueue.isSuspended = true
        let sessionConfiguration = URLSessionConfiguration.default;
        sessionConfiguration.urlCache = nil
        var token = rAuthorizationDictionary["access_token"] as! String

        //init session
        self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

        //fire off the request
        print("Performing GET Request")
        let url = URL(string: rUrl)
        var request = URLRequest(url: url!)
        request.httpMethod = "GET"
        request.addValue("Bearer " + token, forHTTPHeaderField: "Authorization");
        //request.httpBody = rRequest.data(using: .utf8)
        let task = session?.dataTask(with: request, completionHandler: { (data, response, error) in
            let result = NSString(data: data!, encoding: String.Encoding.ascii.rawValue)
            let urlResponse = response as? HTTPURLResponse;
            print("result: \(result)")
            print("response: \(response)")
            print("error: \(error)")

            //init plugin result
            //let jsonResponseDictionary = self.convertToDictionary(text: (response?.description)!);
            let response: Dictionary = [ "status" : "success", "response" : result ] as [String : Any]
            let pluginResult = CDVPluginResult(
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

    //this function will perform the GET request
    @objc(PostRequest:)
    func PostRequest(command: CDVInvokedUrlCommand) {
        print("Initiating Post Connection")

        //assign all variables
        rUrl = command.argument(at: 0) as! String
        rRequest = command.argument(at: 1) as! String
        //rFolder = command.argument(at: 2) as! String
        rFile = "*myglobaldatacom" //command.argument(at: 3) as! String
        //rPassword = command.argument(at: 4) as! String
        //rHostName = command.argument(at: 5) as! String
        rAuthorization = command.argument(at: 6) as! String

        //clear cache
        self.opQueue.isSuspended = true
        let sessionConfiguration = URLSessionConfiguration.default;
        sessionConfiguration.urlCache = nil

        //init session
        self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

        //fire off the request
        print("Performing POST Request")
        let url = URL(string: rUrl)
        var request = URLRequest(url: url!)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type");
        request.httpBody = rRequest.data(using: .utf8)
        let task = session?.dataTask(with: request, completionHandler: { (data, response, error) in
            let result = NSString(data: data!, encoding: String.Encoding.ascii.rawValue)
            let urlResponse = response as? HTTPURLResponse;
            print("result: \(result)")
            print("response: \(response)")
            print("error: \(error)")

            //init plugin result
            //let jsonResponseDictionary = self.convertToDictionary(text: (response?.description)!);
            let response: Dictionary = [ "status" : "success", "response" : result ] as [String : Any]
            let pluginResult = CDVPluginResult(
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




        /*//init plugin result
         var response: Dictionary = [ "response" : "ok", "status" : "success" ] as [String : Any]
         var pluginResult = CDVPluginResult(
         status: CDVCommandStatus_OK,
         messageAs: response
         )

         //send the callback object back
         print("Sending back response")
         self.commandDelegate!.send(
         pluginResult,
         callbackId: command.callbackId
         )*/


    }


    //this override will init when the url session starts
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        //check for server trust challenge
        print("Checking for Trust challenge")
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            print("Performing Trust validation")
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult = SecTrustResultType.invalid
                let status = SecTrustEvaluate(serverTrust, &secresult)

                if(errSecSuccess == status) {
                    if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                        let serverCertificateData = SecCertificateCopyData(serverCertificate)
                        let data = CFDataGetBytePtr(serverCertificateData);
                        let size = CFDataGetLength(serverCertificateData);
                        let cert1 = NSData(bytes: data, length: size)
                        let file_der = Bundle.main.path(forResource: rFile, ofType: "cer")
                        print("Checking for available certificate")
                        if let file = file_der {
                            print("Certificate found. Checking contents of certificate")
                            if let cert2 = NSData(contentsOfFile: file) {
                                //if cert1.isEqual(to: cert2 as Data)
                                //print("Certificates are equal. Setting trust mechanism")*/
                                completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust:serverTrust))
                                print("Trust mechanism established")
                                return
                                //}
                            }
                            print("Certificate not trusted")
                        }
                    }
                }
            }
        }

        // Pinning failed
        completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)

        /*print("URLSession callback initiated. Getting certificate")
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
         completionHandler(URLSession.AuthChallengeDisposition.rejectProtectionSpace, nil)*/
    }

    //this function will convert a json string to a dictionary
    func convertToDictionary(text: String) -> [String: Any]? {
        if let data = text.data(using: .utf8) {
            do {
                return try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
            } catch {
                print(error.localizedDescription)
            }
        }
        return nil
    }


    /*//this function will validate if a certificate is installed within the app file structure or in the keychain of the device
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
     func initGetConnection(command: CDVInvokedUrlCommand) {
     print("Initiating GET Connection")

     //clear cache
     self.opQueue.isSuspended = true
     let sessionConfiguration = URLSessionConfiguration.default;
     sessionConfiguration.urlCache = nil

     //init session
     self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

     //fire off the request
     let url = URL(string: "https://maximo.mosaicco.com")
     var request = URLRequest(url: url!)
     request.httpMethod = "GET"
     let task = session?.dataTask(with: request, completionHandler: { (data, response, error) in
     let result = NSString(data: data!, encoding: String.Encoding.ascii.rawValue)
     let urlResponse = response as? HTTPURLResponse;
     print("result: \(result)")
     print("response: \(response)")
     print("error: \(error)")
     print("Sending back Cordova callback with HTML stream");
     //init plugin result
     let response: Dictionary = [ "html" : result, "status" : true, "headers" : urlResponse?.allHeaderFields ] as [String : Any]
     let pluginResult = CDVPluginResult(
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


     //this function will perform the http connection
     func initPostConnection(command: CDVInvokedUrlCommand) {
     print("Initiating Post Connection")

     //clear cache
     self.opQueue.isSuspended = true
     let sessionConfiguration = URLSessionConfiguration.default;
     sessionConfiguration.urlCache = nil

     //init session
     self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

     //fire off the request
     let url = URL(string: "https://maximo.mosaicco.com")
     var request = URLRequest(url: url!)
     request.httpMethod = "POST"
     let task = session?.dataTask(with: request, completionHandler: { (data, response, error) in
     let result = NSString(data: data!, encoding: String.Encoding.ascii.rawValue)
     let urlResponse = response as? HTTPURLResponse;
     print("result: \(result)")
     print("response: \(response)")
     print("error: \(error)")
     print("Sending back Cordova callback with HTML stream");
     //init plugin result
     let response: Dictionary = [ "html" : result, "status" : true, "headers" : urlResponse?.allHeaderFields ] as [String : Any]
     let pluginResult = CDVPluginResult(
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
     let response: Dictionary = [ "html" : result, "status" : true, "headers" : urlResponse?.allHeaderFields ] as [String : Any]
     let pluginResult = CDVPluginResult(
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
     }*/
}
