/*
 * OpenID Connect project.
 *
 * Copyright 2017-2023 e-Contract.be BV. All rights reserved.
 * e-Contract.be BV proprietary/confidential. Use is subject to license terms.
 */

"use strict";

import ansi from "ansi";
let cursor = ansi(process.stdout);
import express from "express";
let app = express();
import bodyParser from "body-parser";
import { Issuer, custom } from "openid-client";
import { v4 as uuidv4 } from "uuid";
import path from "path";
const __filename = fileURLToPath(import.meta.url);
import { fileURLToPath } from 'url';
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

app.get("/authenticate", function (req, res) {
  Issuer.discover("https://www.e-contract.be/eid-idp/oidc/auth/")
    .then(issuer => {
      console.log("registration_endpoint: " + issuer.registration_endpoint);
      issuer.Client.register({
        "redirect_uris": [
          "http://localhost:3000/landing"
        ]
      })
        .then(client => {
          console.log("client id: " + client.client_id);
          oidcClient = client;
          let state = uuidv4();
          req.session.state = state;
          let nonce = uuidv4();
          req.session.nonce = nonce;
          console.log("state: " + state);
          res.redirect(oidcClient.authorizationUrl({
            redirect_uri: "http://localhost:3000/landing",
            state: state,
            nonce: nonce,
            scope: "openid profile address"
          }));
        })
        .catch(error => {
          console.error("error: " + error);
          console.error(error);
        });
    });
});

app.get("/authenticate-popup", function (req, res) {
  Issuer.discover("https://www.e-contract.be/eid-idp/oidc/ident/")
    .then(issuer => {
      console.log("registration_endpoint: " + issuer.registration_endpoint);
      issuer.Client.register({
        "redirect_uris": [
          "http://localhost:3000/landing-popup"
        ]
      })
        .then(client => {
          console.log("client id: " + client.client_id);
          oidcClient = client;
          let state = uuidv4();
          req.session.state = state;
          let nonce = uuidv4();
          req.session.nonce = nonce;
          console.log("state: " + state);
          res.redirect(oidcClient.authorizationUrl({
            redirect_uri: "http://localhost:3000/landing-popup",
            state: state,
            nonce: nonce,
            scope: "openid profile address"
          }));
        })
        .catch(error => {
          console.error("error: " + error);
          console.error(error);
        });
    });
});

function processAuthentication(req, res) {
  let params = oidcClient.callbackParams(req);
  let checks = {
    state: req.session.state,
    nonce: req.session.nonce
  };
  oidcClient[custom.clock_tolerance] = 5;
  oidcClient.callback("http://localhost:" + PORT + "/landing", params, checks)
    .then(tokenSet => {
      console.log("received and validated tokens %j", tokenSet);
      oidcClient.userinfo(tokenSet.access_token)
        .then(userinfo => {
          console.log("userinfo %j", userinfo);
          res.render("result", {
            userinfo: userinfo
          });
        });
    });
}
app.get("/landing", processAuthentication);

function processAuthenticationPopup(req, res) {
  let params = oidcClient.callbackParams(req);
  let checks = {
    state: req.session.state,
    nonce: req.session.nonce
  };
  oidcClient[custom.clock_tolerance] = 5;
  oidcClient.callback("http://localhost:" + PORT + "/landing-popup", params, checks)
    .then(tokenSet => {
      console.log("received and validated tokens %j", tokenSet);
      oidcClient.userinfo(tokenSet.access_token)
        .then(userinfo => {
          console.log("userinfo %j", userinfo);
          req.session.userinfo = userinfo;
          res.redirect("result-popup.html");
        });
    });
}
app.get("/landing-popup", processAuthenticationPopup);

app.get("/popup-result", function (req, res) {
  res.render("result", {
    userinfo: req.session.userinfo
  });
});

let oidcClient;

let server = app.listen(PORT, function () {
  let host = server.address().address;
  let port = server.address().port;
  cursor.fg.blue();
  cursor.bold();
  cursor.write("Example eID Identity Provifer OpenID Connect NodeJS application listening at http://" + host + ":" + port + "\n");
  cursor.fg.red();
  cursor.write("Copyright (C) 2017-2023 e-Contract.BV\n");
  cursor.fg.reset();
  cursor.write("\n");
});
