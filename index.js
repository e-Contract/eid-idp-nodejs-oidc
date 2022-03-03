/*
 * OpenID Connect project.
 *
 * Copyright 2017-2022 e-Contract.be BV. All rights reserved.
 * e-Contract.be BV proprietary/confidential. Use is subject to license terms.
 */

"use strict";

let ansi = require('ansi');
let cursor = ansi(process.stdout);
let express = require('express');
let app = express();
let bodyParser = require('body-parser');
let Issuer = require('openid-client').Issuer;
const { v4: uuidv4 } = require('uuid');

const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: false }));

let session = require('express-session');
app.use(session({
  secret: 'mySecretKey',
  resave: false,
  saveUninitialized: true
}));

app.set('views', __dirname + '/views');
app.set('view engine', 'pug');

app.use(express.static(__dirname + "/public"));

app.get("/authenticate", function (req, res) {
  let state = uuidv4();
  req.session.state = state;
  let nonce = uuidv4();
  req.session.nonce = nonce;
  console.log("state: " + state);
  res.redirect(Client.authorizationUrl({
    redirect_uri: "http://localhost:3000/landing",
    state: state,
    nonce: nonce,
    scope: "openid profile address"
  }));
});

function processAuthentication(req, res) {
  let params = Client.callbackParams(req);
  let checks = {
    state: req.session.state,
    nonce: req.session.nonce
  };
  Client.callback("http://localhost:" + PORT + "/landing", params, checks)
    .then(tokenSet => {
      console.log('received and validated tokens %j', tokenSet);
      Client.userinfo(tokenSet.access_token)
        .then(userinfo => {
          console.log('userinfo %j', userinfo);
          res.render('result', {
            userinfo: userinfo
          });
        });
    });
}

app.get("/landing", processAuthentication);

let Client;
// https://www.e-contract.be/eid-idp/oidc/auth/
// https://www.e-contract.be/eid-idp/oidc/ident/
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
        Client = client;
      })
      .catch(error => {
        console.error("error: " + error);
        console.error(error);
      });
  });

let server = app.listen(PORT, function () {
  let host = server.address().address;
  let port = server.address().port;
  cursor.fg.blue();
  cursor.bold();
  cursor.write("Example eID Identity Provifer OpenID Connect NodeJS application listening at http://" + host + ":" + port + "\n");
  cursor.fg.red();
  cursor.write("Copyright (C) 2017-2022 e-Contract.BV\n");
  cursor.fg.reset();
  cursor.write("\n");
});
