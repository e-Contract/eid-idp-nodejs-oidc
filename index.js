/*
 * OpenID Connect project.
 *
 * Copyright 2017-2025 e-Contract.be BV. All rights reserved.
 * e-Contract.be BV proprietary/confidential. Use is subject to license terms.
 */

"use strict";

import ansi from "ansi";
import express from "express";
import bodyParser from "body-parser";
import * as oauth from "oauth4webapi";
import path from "path";
import { fileURLToPath } from 'url';

let cursor = ansi(process.stdout);
let app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: false }));

import session from "express-session";
app.use(session({
  secret: "mySecretKey",
  resave: false,
  saveUninitialized: true
}));

app.set("views", __dirname + "/views");
app.set("view engine", "pug");

app.use(express.static(__dirname + "/public"));

app.get("/authenticate", async function (request, response) {
  let issuer = new URL("https://www.e-contract.be/eid-idp/oidc/auth/");
  const redirect_uri = "http://localhost:3000/landing";
  const authorizationServer = await oauth.discoveryRequest(issuer)
    .then((response) => oauth.processDiscoveryResponse(issuer, response));
  request.session.authorizationServer = authorizationServer;

  const client = await oauth.dynamicClientRegistrationRequest(authorizationServer, {
    redirect_uris: [
      redirect_uri
    ]
  })
    .then((registrationResponse) => oauth.processDynamicClientRegistrationResponse(registrationResponse));
  request.session.client = client;
  request.session.state = oauth.generateRandomState();
  request.session.nonce = oauth.generateRandomNonce();
  request.session.code_verifier = oauth.generateRandomCodeVerifier();
  const code_challenge = await oauth.calculatePKCECodeChallenge(request.session.code_verifier);
  let authorizationUrl = new URL(authorizationServer.authorization_endpoint);
  authorizationUrl.searchParams.set("client_id", client.client_id);
  authorizationUrl.searchParams.set("redirect_uri", redirect_uri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", "openid profile address photo");
  authorizationUrl.searchParams.set("code_challenge", code_challenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
  authorizationUrl.searchParams.set("state", request.session.state);
  authorizationUrl.searchParams.set("nonce", request.session.nonce);
  response.redirect(authorizationUrl);
});

app.get("/authenticate-popup", async function (request, response) {
  let issuer = new URL("https://www.e-contract.be/eid-idp/oidc/ident/");
  const redirect_uri = "http://localhost:3000/landing-popup";
  const authorizationServer = await oauth.discoveryRequest(issuer)
    .then((response) => oauth.processDiscoveryResponse(issuer, response));
  request.session.authorizationServer = authorizationServer;

  const client = await oauth.dynamicClientRegistrationRequest(authorizationServer, {
    redirect_uris: [
      redirect_uri
    ]
  })
    .then((registrationResponse) => oauth.processDynamicClientRegistrationResponse(registrationResponse));
  request.session.client = client;
  request.session.state = oauth.generateRandomState();
  request.session.nonce = oauth.generateRandomNonce();
  request.session.code_verifier = oauth.generateRandomCodeVerifier();
  const code_challenge = await oauth.calculatePKCECodeChallenge(request.session.code_verifier);
  let authorizationUrl = new URL(authorizationServer.authorization_endpoint);
  authorizationUrl.searchParams.set("client_id", client.client_id);
  authorizationUrl.searchParams.set("redirect_uri", redirect_uri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", "openid profile address photo");
  authorizationUrl.searchParams.set("code_challenge", code_challenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
  authorizationUrl.searchParams.set("state", request.session.state);
  authorizationUrl.searchParams.set("nonce", request.session.nonce);
  response.redirect(authorizationUrl);
});

function processAuthentication(request, response) {
  let params = new URLSearchParams(request.url.substring("/landing?".length));
  let callbackParams = oauth.validateAuthResponse(request.session.authorizationServer,
    request.session.client,
    params,
    request.session.state
  );
  const redirect_uri = "http://localhost:3000/landing";
  const clientAuth = oauth.ClientSecretPost(request.session.client.client_secret)

  oauth.authorizationCodeGrantRequest(request.session.authorizationServer,
    request.session.client,
    clientAuth,
    callbackParams,
    redirect_uri,
    request.session.code_verifier
  )
    .then((response) => {
      return oauth.processAuthorizationCodeResponse(request.session.authorizationServer,
        request.session.client,
        response,
        {
          expectedNonce: request.session.nonce
        });
    })
    .then((tokenEndpointResponse) => {
      return oauth.userInfoRequest(request.session.authorizationServer,
        request.session.client,
        tokenEndpointResponse.access_token);
    })
    .then((response) => {
      return oauth.processUserInfoResponse(request.session.authorizationServer,
        request.session.client,
        oauth.skipSubjectCheck,
        response);
    })
    .then((userInfoResponse) => {
      if ("urn:be:e-contract:idp:oidc:acr:auth" !== userInfoResponse.acr) {
        throw new Error("incorrect ACR");
      }
      response.render("result", {
        userinfo: userInfoResponse
      });
    });
}
app.get("/landing", processAuthentication);

function processAuthenticationPopup(request, response) {
  let params = new URLSearchParams(request.url.substring("/landing-popup?".length));
  let callbackParams = oauth.validateAuthResponse(request.session.authorizationServer,
    request.session.client,
    params,
    request.session.state
  );
  const redirect_uri = "http://localhost:3000/landing-popup";
  const clientAuth = oauth.ClientSecretPost(request.session.client.client_secret)

  oauth.authorizationCodeGrantRequest(request.session.authorizationServer,
    request.session.client,
    clientAuth,
    callbackParams,
    redirect_uri,
    request.session.code_verifier
  )
    .then((response) => {
      return oauth.processAuthorizationCodeResponse(request.session.authorizationServer,
        request.session.client,
        response,
        {
          expectedNonce: request.session.nonce
        });
    })
    .then((tokenEndpointResponse) => {
      return oauth.userInfoRequest(request.session.authorizationServer,
        request.session.client,
        tokenEndpointResponse.access_token);
    })
    .then((response) => {
      return oauth.processUserInfoResponse(request.session.authorizationServer,
        request.session.client,
        oauth.skipSubjectCheck,
        response);
    })
    .then((userInfoResponse) => {
      if ("urn:be:e-contract:idp:oidc:acr:ident" !== userInfoResponse.acr) {
        throw new Error("incorrect ACR");
      }
      request.session.userinfo = userInfoResponse;
      response.redirect("result-popup.html");
    });
}
app.get("/landing-popup", processAuthenticationPopup);

app.get("/popup-result", function (req, res) {
  res.render("result", {
    userinfo: req.session.userinfo
  });
});

let server = app.listen(PORT, function () {
  let host = server.address().address;
  let port = server.address().port;
  cursor.fg.blue();
  cursor.bold();
  cursor.write("Example eID Identity Provider OpenID Connect NodeJS application listening at http://" + host + ":" + port + "\n");
  cursor.fg.red();
  cursor.write("Copyright (C) 2017-2025 e-Contract.BV\n");
  cursor.fg.reset();
  cursor.write("\n");
});
