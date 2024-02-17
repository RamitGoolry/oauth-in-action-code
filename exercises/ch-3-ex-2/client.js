let express = require("express");
let request = require("sync-request");
let url = require("url");
let qs = require("qs");
let querystring = require('querystring');
let cons = require('consolidate');
let randomstring = require("randomstring");
let __ = require('underscore');
__.string = require('underscore.string');


let app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
let authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token'
};

let client = {
  "client_id": "oauth-client-1",
  "client_secret": "oauth-client-secret-1",
  "redirect_uris": ["http://localhost:9000/callback"],
  "scope": "foo"
};

let protectedResource = 'http://localhost:9002/resource';

let state = null;

let access_token = '987tghjkiu6trfghjuytrghj';
let scope = null;
let refresh_token = 'j2r3oj32r23rmasd98uhjrk2o3i';

app.get('/', function(_, res) {
  res.render('index', { access_token, scope, refresh_token });
});

app.get('/authorize', function(_, res) {

  access_token = null;
  scope = null;
  state = randomstring.generate();

  let authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: 'code',
    scope: client.scope,
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state: state
  });

  console.log("redirect", authorizeUrl);
  res.redirect(authorizeUrl);
});

app.get('/callback', function(req, res) {

  if (req.query.error) {
    // it's an error response, act accordingly
    res.render('error', { error: req.query.error });
    return;
  }

  let resState = req.query.state;
  if (resState != state) {
    console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
    res.render('error', { error: 'State value did not match' });
    return;
  }

  let code = req.query.code;

  let form_data = qs.stringify({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: client.redirect_uris[0]
  });
  let headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
  };

  let tokRes = request('POST', authServer.tokenEndpoint,
    {
      body: form_data,
      headers: headers
    }
  );

  console.log('Requesting access token for code %s', code);

  if (tokRes.statusCode < 200 || tokRes.statusCode >= 300) {
    res.render('error', { error: 'Unable to fetch access token, server response: ' + tokRes.statusCode });
    return;
  }

  let body = JSON.parse(tokRes.getBody());

  access_token = body.access_token;
  console.log('Got access token: %s', access_token);
  if (body.refresh_token) {
    refresh_token = body.refresh_token;
    console.log('Got refresh token: %s', refresh_token);
  }

  scope = body.scope;
  console.log('Got scope: %s', scope);

  res.render('index', { access_token: access_token, scope: scope, refresh_token: refresh_token });
});

app.get('/fetch_resource', function(req, res) {

  console.log('Making request with access token %s', access_token);

  let headers = {
    'Authorization': 'Bearer ' + access_token,
    'Content-Type': 'application/x-www-form-urlencoded'
  };

  let resource = request('POST', protectedResource,
    { headers: headers }
  );

  if (resource.statusCode < 200 || resource.statusCode >= 300) {
    access_token = null;
    if (!refresh_token) {
      console.log("resource status error code " + resource.statusCode);
      res.render('error', { error: 'Unable to fetch resource. Status ' + resource.statusCode });
    }
    refreshAccessToken(req, res);
  }

  let body = JSON.parse(resource.getBody());
  res.render('data', { resource: body });
});

let refreshAccessToken = function(_, res) {
  console.log('Refreshing access token');
  let form_data = qs.stringify({
    grant_type: 'refresh_token',
    refresh_token: refresh_token
  });
  let headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
  };

  let tokenResponse = request('POST', authServer.tokenEndpoint,
    {
      body: form_data,
      headers: headers
    }
  );

  let body = JSON.parse(tokenResponse.getBody());
  access_token = body.access_token;
  if (body.refresh_token) {
    refresh_token = body.refresh_token;
  }

  // NOTE: We just have one /fetch_resource endpoint so we can simply redirect to it, but 
  // in a real app we would probably want to store the path and query string of the original request, 
  // or store a callback function to be invoked after the access token has been refreshed
  res.redirect('/fetch_resource');
};

let buildUrl = function(base, options, hash) {
  let newUrl = url.parse(base, true);
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

let encodeClientCredentials = function(clientId, clientSecret) {
  return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

let server = app.listen(9000, 'localhost', function() {
  let host = server.address().address;
  let port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});

