var exec = require('cordova/exec');

//this function will perform the GET request
exports.performGetRequest = function(args, success, error) {
  exec(success, error, "MobileSSLPinningUtility", "GetRequest", args);
};

//this function will perform the POST request
exports.performPostRequest = function(args, success, error) {
  exec(success, error, "MobileSSLPinningUtility", "PostRequest", args);
};

exports.coolMethod = function(arg0, success, error) {
    exec(success, error, "MobileSSLPinningUtility", "coolMethod", [arg0]);
};
