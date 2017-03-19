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
        rFile = "myglobaldatacom" //command.argument(at: 3) as! String
        //rPassword = command.argument(at: 4) as! String
        //rHostName = command.argument(at: 5) as! String
        rAuthorization = command.argument(at: 6) as! String
        var rAuthorizationDictionary = convertToDictionary(text: rAuthorization)!

        //clear cache
        self.opQueue.isSuspended = true
        let sessionConfiguration = URLSessionConfiguration.default;
        sessionConfiguration.urlCache = nil
        let token = rAuthorizationDictionary["access_token"] as! String

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
        rFile = "myglobaldatacom" //command.argument(at: 3) as! String
        //rPassword = command.argument(at: 4) as! String
        //rHostName = command.argument(at: 5) as! String
        rAuthorization = command.argument(at: 6) as! String
        var rAuthorizationDictionary = convertToDictionary(text: rAuthorization)!

        //clear cache
        self.opQueue.isSuspended = true
        let sessionConfiguration = URLSessionConfiguration.default;
        sessionConfiguration.urlCache = nil

        //check if the authorization dictionary has values
        var token: String = ""
        if(rAuthorizationDictionary.values.count > 0) {
            //grab the token
            token = rAuthorizationDictionary["access_token"] as! String
        }

        //init session
        self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

        //fire off the request
        print("Performing POST Request with request - " + rRequest)
        let url = URL(string: rUrl)
        var request = URLRequest(url: url!)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type");
        //check if the token is found
        if(!token.isEmpty) {
            request.addValue("Bearer " + token, forHTTPHeaderField: "Authorization");
        }
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
}
