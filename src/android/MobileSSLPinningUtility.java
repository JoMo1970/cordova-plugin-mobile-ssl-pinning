package com.mobile.ssl.pinning.utility.plugin;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;
import android.content.Context;
import android.widget.Toast;
import android.app.Activity;
import android.content.Intent;
import android.provider.Settings;
import android.content.res.Resources;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.KeyStore;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class MobileSSLPinningUtility extends CordovaPlugin {

  //private variables
  private final String PERFORMGETREQUESTPARAM = "GetRequest";
  private final String PERFORMPOSTREQUESTPARAM = "PostRequest";
  private String rHostName = "";
  private String rAuthorization = "";


  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    //get all required items
    String rUrl = args.getString(0);
    String rRequest = args.getString(1);
    String rFolder = args.getString(2);
    String rFile = args.getString(3);
    String rPassword = args.getString(4);
    this.rHostName = args.getString(5);
    this.rAuthorization = getJsonValue(args.getString(6), "access_token");
    JSONObject jsonObject = new JSONObject();

    //check to see if the installed directory exists
    Log.d("INFO", "Checking for " + rFolder + " in the app folder structure");
    Boolean directoryExists = this.containsRawClass(rFolder);
    if(directoryExists) {
      //check for the installed keystore by filename
      Log.d("INFO", "Found " + rFolder + " in the app structure");
      int resId = this.ckKeystoreExists(rFile, this.getRawClass(rFolder));
      if(resId !=0) {
        //check for GET request
        Log.d("INFO", "Found " + resId + " in the app structure");
        if (PERFORMGETREQUESTPARAM.equals(action)) {
          Log.d("INFO", "Invoking " + action);
          //init the ssl context
          SSLContext sslContext = getSSLContext(resId, rPassword);
          //perform the GET request
          jsonObject.put("status", "success");
          jsonObject.put("response", this.performHTTPSGetConnection(sslContext, rUrl, rHostName));
          callbackContext.success(jsonObject);
          return true;
        }
        //check for POST request
        else if(PERFORMPOSTREQUESTPARAM.equals(action)) {
          Log.d("INFO", "Invoking " + action);
          //init the ssl context
          SSLContext sslContext = getSSLContext(resId, rPassword);
          //perform the GET request
          jsonObject.put("status", "success");
          jsonObject.put("response", this.performHTTPSPostConnection(sslContext, rUrl, rRequest, rHostName));
          callbackContext.success(jsonObject);
          return true;
        }
      }
      else {
        Log.d("INFO", rFile + " does not exist in the app structure");
        jsonObject.put("status", "failure");
        jsonObject.put("response", "Keystore does not exist");
        callbackContext.success(jsonObject);
      }
    }
    else {
      Log.d("INFO", rFolder + " does not exist in the app structure");
      jsonObject.put("status", "failure");
      jsonObject.put("response", "Keystore directory does not exist");
      callbackContext.success(jsonObject);
    }
    return false;
  }

  private void echo(
    String msg,
    CallbackContext callbackContext
  ) {
    if (msg == null || msg.length() == 0) {
      callbackContext.error("Empty message!");
    } else {
      Toast.makeText(
        webView.getContext(),
        msg,
        Toast.LENGTH_LONG
      ).show();
      callbackContext.success(msg);
    }
  }

  //this function will check if the R class contains the sub-class raw
  private Boolean containsRawClass(String className) {
      try {
          Class <?> rClass = Class.forName(this.cordova.getActivity().getPackageName() + ".R");
          Class[] rawClasses = rClass.getClasses();
          for(Class c : rawClasses) {
              if(c.getSimpleName().equals(className)) {
                  return true;
              }
          }
          return false;
      }
      catch(Exception ex) {
          return false;
      }
  }

  private Class<?> getRawClass(String className) {
      try {
          Class <?> rClass = Class.forName(this.cordova.getActivity().getPackageName() + ".R");
          Class[] rawClasses = rClass.getClasses();
          for(Class c : rawClasses) {
              if(c.getSimpleName().equals(className)) {
                  return c;
              }
          }
          return null;
      }
      catch(Exception ex) {
          return null;
      }
  }

  //this function will check if the p12 resource file is available
  private int ckKeystoreExists(String variableName, Class<?> c) {
      //init local variables
      Field field = null;
      int resId = 0;

      try {
          field = c.getField(variableName);
          try {
              resId = field.getInt(null);
              Log.d("INFO", "Found field. Returning true");
              return resId;
          }
          catch (Exception e) {
              Log.d("INFO", "Res Id not found. Sending back negative");
              return resId;
          }
      }
      catch(Exception ex) {
          Log.d("INFO", "Field not found. Sending back negative");
          return resId;
      }
  }

  /*//this function will perform post execution
  private void completeRequest(String response) throws JSONException {
      Log.d("INFO", "Request Completed: " + response);
      responseJSON.put("status", true);
      responseJSON.put("html", response);
      callback.success(responseJSON);
      Log.d("INFO", "Response sent back");
  }*/

  //this function will init the ssl context
  private SSLContext getSSLContext(int resId, String password) {
      Log.d("INFO", "Creating SSLContext from " + resId + " and " + password);
      try {
          //init trust store from input stream
          KeyStore trusted = KeyStore.getInstance("BKS");
          InputStream in = this.cordova.getActivity().getResources().openRawResource(resId);
          trusted.load(in, password.toCharArray());
          in.close();
          Log.d("INFO", "Trust Store initialized");

          //init the trust manufacturer factory
          TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
          tmf.init(trusted);
          TrustManager[] trustManagers = tmf.getTrustManagers();
          Log.d("INFO", "Trust manager initialized");

          /*//init keystore for pkcs type for the ssl connection; load the file
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          keyStore.load(is, password.toCharArray());

          //init the ssl key managers
          KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
          kmf.init(keyStore, password.toCharArray());
          KeyManager[] keyManagers = kmf.getKeyManagers();*/

          //init ssl context
          SSLContext sslContext = SSLContext.getInstance("TLS");
          sslContext.init(null, trustManagers, null);
          Log.d("INFO", "SSLContext initialized");
          return sslContext;
      } catch (Exception ex) {
          Log.d("INFO", "Exception when creating SSLContext: " + ex.toString());
          return null;
      }
  }

  //this function will parse out the json string and retrieve the passed variables
  private String getJsonValue(String jsonString, String jsonKey) {
    try {
      //parse the incoming json String
      JSONObject incomingJSON = new JSONObject(jsonString);
      return incomingJSON.getString(jsonKey);
    }
    catch(Exception ex) {
      return "";
    }
  }

  //this function will perform the http connection
  private String performHTTPSGetConnection(SSLContext sslContext, String url, String hostName, String authJson) {
      //init https connection and jsonResponse object
      Log.d("INFO", "Performing HTTP GET Connection");
      HttpsURLConnection httpsURLConnection = null;
      try {
          //init local variables
          String result = null;
          URL requestedUrl = new URL(url);

          //init https connection and return resposne
          httpsURLConnection = (HttpsURLConnection) requestedUrl.openConnection();
          httpsURLConnection.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
              HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
              return hv.verify(rHostName, session);
              //return true;
            }
          });
          httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());
          //check for the authorization String
          if(this.rAuthorization!="") {
            httpsURLConnection.setRequestProperty("Authorization", "Bearer " + this.rAuthorization);
          }
          httpsURLConnection.setRequestMethod("GET");
          httpsURLConnection.setConnectTimeout(30000);
          httpsURLConnection.setReadTimeout(30000);
          Log.d("INFO", "Return response from GET request");
          return parseResponseStream(httpsURLConnection.getInputStream());
      } catch (Exception ex) {
          Log.d("INFO", ex.toString());
          return ex.toString();
      }
      finally {
          //check if the connection is not null and close
          if(httpsURLConnection!=null) {
              httpsURLConnection.disconnect();
          }
      }
  }

  //this function will perform the http connection
  private String performHTTPSPostConnection(SSLContext sslContext, String url, String request, String hostName) {
      //init https connection and jsonResponse object
      Log.d("INFO", "Performing HTTP POST Connection");
      HttpsURLConnection httpsURLConnection = null;
      try {
          //init local variables
          String result = null;
          URL requestedUrl = new URL(url);

          //init https connection and return resposne
          httpsURLConnection = (HttpsURLConnection) requestedUrl.openConnection();
          httpsURLConnection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
          httpsURLConnection.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
              HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
              return hv.verify(rHostName, session);
              //return true;
            }
          });
          httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());
          //check for the authorization String
          if(this.rAuthorization!="") {
            httpsURLConnection.setRequestProperty("Authorization", "Bearer " + this.rAuthorization);
          }
          httpsURLConnection.setRequestMethod("POST");
          httpsURLConnection.setConnectTimeout(30000);
          httpsURLConnection.setReadTimeout(30000);
          httpsURLConnection.setDoOutput(true);
          httpsURLConnection.setDoInput(true);

          //write the data to the server
          Log.d("INFO", "Writing POST body to stream");
          OutputStream os = httpsURLConnection.getOutputStream();
          os.write(request.getBytes("UTF-8"));
          os.close();

          //returm the data
          Log.d("INFO", "Returning response from POST request");
          return parseResponseStream(httpsURLConnection.getInputStream());
      } catch (Exception ex) {
          Log.d("INFO", ex.toString());
          return ex.toString();
      }
      finally {
          //check if the connection is not null and close
          if(httpsURLConnection!=null) {
              httpsURLConnection.disconnect();
          }
      }
  }

  //this function will parse out the returned stream
  private String parseResponseStream(InputStream stream) {
      try {
          BufferedReader br = new BufferedReader(new InputStreamReader(stream));
          StringBuilder sb = new StringBuilder();
          String line;
          while((line = br.readLine()) != null) {
              sb.append(line + "\n");
          }
          br.close();
          return sb.toString();
      }
      catch(Exception ex) {
          Log.d("INFO", "ERROR: " + ex.toString());
          return "";
      }
  }

  /*//this object will act as the payload for the asynctask
  private class AsyncPayload {
      private InputStream stream;
      private String password;

      public void setStream(InputStream newStream) {
          this.stream = newStream;
      }
      public InputStream getInputStream() {
          return this.stream;
      }
      public void setPassword(String newPassword) {
          this.password = newPassword;
      }
      public String getPassword() {
          return this.password;
      }
  }*/
}
