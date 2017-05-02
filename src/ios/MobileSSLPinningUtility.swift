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
    var rStartDate: String = "";
    var rEndDate: String = "";

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
        rStartDate = command.argument(at: 7) as! String
        rEndDate = command.argument(at: 8) as! String

        //clear cache
        self.opQueue.isSuspended = true
        let sessionConfiguration = URLSessionConfiguration.default;
        sessionConfiguration.urlCache = nil


        /*//check if the authorization dictionary has values
        var token: String = ""
        if(!rAuthorization.isEmpty) {
            //grab the token
            var rAuthorizationDictionary = convertToDictionary(text: rAuthorization)!
            token = rAuthorizationDictionary["access_token"] as! String
        }*/

        //init session
        self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

        //fire off the request
        print("Performing GET Request")
        let url = URL(string: rUrl)
        var request = URLRequest(url: url!)
        request.httpMethod = "GET"
        //request.addValue("Bearer " + token, forHTTPHeaderField: "Authorization");
        request.addValue("Bearer " + rAuthorization, forHTTPHeaderField: "Authorization");
        //check if the start and end date values are empty
        if(!rStartDate.isEmpty && !rEndDate.isEmpty) {
            request.addValue(rStartDate, forHTTPHeaderField: "start_date");
            request.addValue(rEndDate, forHTTPHeaderField: "end_date");
        }

        //init the task and invoke
        let task = session?.dataTask(with: request, completionHandler: { (data, response, error) in
            print("Get task as completed");
            //check for error
            if(error != nil) {
                print(error!);
            }
            else {
                print("Get task response is normal. Processing response")
                //check if the result is null
                var responseDictionary: Dictionary = [ "status" : "success", "response" : nil ] as [String : Any]
                if let result = String(data: data!, encoding: .utf8) {
                    //set the response with data
                    responseDictionary = [ "status" : "success", "response" : result ] as [String : Any]
                }
                //init the plugin result and send the response
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK,
                    messageAs: responseDictionary
                )
                self.commandDelegate!.send(pluginResult,callbackId: command.callbackId)
            }
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


        //clear cache
        self.opQueue.isSuspended = true
        let sessionConfiguration = URLSessionConfiguration.default;
        sessionConfiguration.urlCache = nil

        /*//check if the authorization dictionary has values
        var token: String = ""
        if(!rAuthorization.isEmpty) {
            //grab the token
            var rAuthorizationDictionary = convertToDictionary(text: rAuthorization)!
            token = rAuthorizationDictionary["access_token"] as! String
        }*/

        //init session
        self.session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: self.opQueue)

        //fire off the request
        print("Performing POST Request with request - " + rRequest)
        let url = URL(string: rUrl)
        var request = URLRequest(url: url!)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type");
        //check if the token is found
        if(!rAuthorization.isEmpty) {
            request.addValue("Bearer " + rAuthorization, forHTTPHeaderField: "Authorization");
        }
        request.httpBody = rRequest.data(using: .utf8)

        //init the task and invoke
        let task = session?.dataTask(with: request, completionHandler: { (data, response, error) in
            print("Post task as completed");
            //check for error
            if(error != nil) {
                print(error!);
            }
            else {
                print("Post task response is normal. Processing response")
                //check if the result is null
                var responseDictionary: Dictionary = [ "status" : "success", "response" : nil ] as [String : Any]
                if let result = String(data: data!, encoding: .utf8) {
                    //set the response with data
                    responseDictionary = [ "status" : "success", "response" : result ] as [String : Any]
                }
                //init the plugin result and send the response
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK,
                    messageAs: responseDictionary
                )
                self.commandDelegate!.send(pluginResult,callbackId: command.callbackId)
            }
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
