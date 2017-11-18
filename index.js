#!/usr/bin/env node

var packageJson = require("./package.json");

var AWS = require("aws-sdk");
var AWSCognito = require("amazon-cognito-identity-js");
var apigClientFactory = require("aws-api-gateway-client").default;
var WindowMock = require("window-mock").default;

var argv = require("./secrets.json");

global.window = { localStorage: new WindowMock().localStorage };
global.navigator = function() {
  return null;
};

function authenticate(callback) {
  var poolData = {
    UserPoolId: argv.userPoolId,
    ClientId: argv.appClientId
  };

  AWS.config.update({ region: argv.cognitoRegion });
  var userPool = new AWSCognito.CognitoUserPool(poolData);

  var userData = {
    Username: argv.username,
    Pool: userPool
  };
  var authenticationData = {
    Username: argv.username,
    Password: argv.password
  };
  var authenticationDetails = new AWSCognito.AuthenticationDetails(
    authenticationData
  );

  var cognitoUser = new AWSCognito.CognitoUser(userData);

  console.log("Authenticating with User Pool");

  cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: function(result) {
      console.log("Success!");
      callback(
        result.getIdToken().getJwtToken(), 
        result.getAccessToken().getJwtToken()
      );
    },
    onFailure: function(err) {
      console.log("Fail!")
      console.log(err.message ? err.message : err);
    },
    newPasswordRequired: function(userAttributes, requiredAttributes) {
      console.log("Changing password");
      delete userAttributes.email_verified;
      
      // unsure about this field, but I don't send this back
      delete userAttributes.phone_number_verified;
  
      // Get these details and call
      cognitoUser.completeNewPasswordChallenge(argv.newPassword, userAttributes, this);
    },
    mfaRequired: function() {
      console.log("MFA is not currently supported");
    },
    customChallenge: function() {
      console.log("Custom challenge is not currently supported");
    },
  });
}

function getCredentials(userToken, accessToken, callback) {
  console.log("Getting temporary credentials");

  var logins = {};

  logins[
    "cognito-idp." + argv.cognitoRegion + ".amazonaws.com/" + argv.userPoolId
  ] = userToken;

  AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: argv.identityPoolId,
    Logins: logins
  });

  AWS.config.credentials.get(function(err) {
    if (err) {
      console.log(err.message ? err.message : err);
      return;
    }
    callback(accessToken);
  });
}

function getUnauthorizedCredentials(callback) {
  console.log("Getting temporary for unauthorized user credentials");

  AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: argv.identityPoolId,
  });

  AWS.config.update({ region: argv.cognitoRegion });
  
  AWS.config.credentials.get(function(err) {
    if (err) {
      console.log(err.message ? err.message : err);
      return;
    }

    callback();
  });
}

function makeRequest(accessToken) {
  console.log("Making API request");
  var apigClient = apigClientFactory.newClient({
    accessKey: AWS.config.credentials.accessKeyId,
    secretKey: AWS.config.credentials.secretAccessKey,
    sessionToken: AWS.config.credentials.sessionToken,
    region: argv.apiGatewayRegion,
    invokeUrl: argv.invokeUrl
  });

  var params = {};
  var additionalParams = {
    queryParams: {
      query: argv.query
    }, 
  };
  var body = ""

  if (accessToken) {
    additionalParams.headers = { accessToken }
  }

  apigClient
    .invokeApi(params, argv.pathTemplate, argv.method, additionalParams, body)
    .then(function(result) {
      console.dir({
        status: result.status,
        statusText: result.statusText,
        data: result.data
      });
    })
    .catch(function(result) {
      if (result.response) {
        console.dir({
          status: result.response.status,
          statusText: result.response.statusText,
          data: result.response.data
        });
      } else {
        console.log(result.message);
      }
    });
}

console.log('#### Unauthorized request ####')
getUnauthorizedCredentials(makeRequest)

authenticate(function(userToken, accessToken) {
  console.log('#### Authorized request ####')  
  getCredentials(userToken, accessToken, makeRequest);
});
