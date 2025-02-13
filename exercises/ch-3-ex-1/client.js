var express = require("express");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token'
};

var client = {
  "client_id": "oauth-client-1",
  "client_secret": "oauth-client-secret-1",
  "redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

var state = randomstring.generate();

var access_token = null;
var scope = null;

app.get('/', function(_, res) {
  res.render('index', { access_token: access_token, scope: scope });
});

app.get('/authorize', function(_, res) {
  console.log("redirecting to authorization server");
  let authorizationUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state: state
  });

  res.redirect(authorizationUrl);
});

app.get('/callback', function(req, res) {
  if (req.query.state != state) {
    res.render('error', { error: 'State value didn\'t match' });
    return;
  }

  let code = req.query.code;
  console.log('/callback called back with code: ' + code);

  let form_data = qs.stringify({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: client.redirect_uris[0]
  });

  let tokenResponse = request('POST', authServer.tokenEndpoint, {
    body: form_data,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
    },
  });

  let responseBody = JSON.parse(tokenResponse.getBody());
  access_token = responseBody.access_token;

  res.render('index', { access_token });
});

app.get('/fetch_resource', function(_, res) {
  if (!access_token) {
    res.render('error', { error: 'Missing access token' });
    return;
  }

  let resourceResponse = request('POST', protectedResource, {
    headers: {
      'Authorization': 'Bearer ' + access_token
    }
  });

  if (resourceResponse.statusCode < 200 || resourceResponse.statusCode >= 300) {
    // Invalid response
    res.render('error', { error: 'Server returned response code: ' + resourceResponse.statusCode })
  }

  let body = JSON.parse(resourceResponse.getBody());

  res.render('data', { resource: body });
  return;
});

var buildUrl = function(base, options, hash) {
  var newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, function(value, key, _) {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

var encodeClientCredentials = function(clientId, clientSecret) {
  return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function() {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});

