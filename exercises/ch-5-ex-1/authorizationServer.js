var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [
  {
    client_id: 'oauth-client-1',
    client_secret: 'oauth-client-secret-1',
    redirect_uris: ['http://localhost:9000/callback'],
  }
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
  return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(_, res) {
  res.render('index', { clients: clients, authServer: authServer });
});

app.get("/authorize", function(req, res) {
  let client = getClient(req.query.client_id);
  if (!client) {
    res.render('error', { error: 'Unknown client' });
    return;
  } else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
    res.render('error', { error: 'Invalid redirect URI' });
    return;
  }

  let request_id = randomstring.generate(8);
  requests[request_id] = req.query;

  res.render('approve', { client, reqid: request_id });
});

app.post('/approve', function(req, res) {
  let reqid = req.body.reqid;
  let query = requests[reqid];
  delete requests[reqid];

  if (!query) {
    res.render('error', { error: 'No matching authorization request' });
    return;
  }

  if (!req.body.approve) {
    let denyUrl = buildUrl(query.redirect_uri, {
      error: 'access_denied'
    });
    res.redirect(denyUrl);
    return;
  }

  switch (query.response_type) {
    case 'code': // Authorization Code grant type
      let authorizationCode = randomstring.generate(8);
      codes[authorizationCode] = {
        request: query,
      };
      let urlParsed = buildUrl(query.redirect_uri, {
        code: authorizationCode,
        state: query.state,
      })
      res.redirect(urlParsed);
      return;

    default:
      let unsupportedUrl = buildUrl(query.redirect_uri, {
        error: 'unsupported_response_type'
      });
      res.redirect(unsupportedUrl);
      return;
  }
});

app.post("/token", function(req, res) {
  let clientId;
  let clientSecret;

  let auth = req.headers['authorization'];
  if (auth) {
    let clientCredentials = decodeClientCredentials(auth);
    clientId = clientCredentials.id;
    clientSecret = clientCredentials.secret;
  }

  if (req.body.client_id) {
    if (clientId) {
      res.status(401).json({
        error: 'Invalid Client'
      });
      return;
    }
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  let client = getClient(clientId);
  if (!client) {
    res.status(401).json({
      error: 'Invalid Client'
    });
    return;
  }

  if (client.client_secret != clientSecret) {
    res.status(401).json({
      error: 'Invalid Client'
    });
    return;
  }

  switch (req.body.grant_type) {
    case 'authorization_code':
      let authorizationCode = codes[req.body.code];
      if (!authorizationCode) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
      delete codes[authorizationCode];

      if (authorizationCode.request.client_id != clientId) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      let accessToken = randomstring.generate();
      nosql.insert({
        access_token: accessToken,
        client_id: clientId
      });

      let tokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
      };

      res.status(200).json(tokenResponse);
      return;

    default:
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
  }
});

var buildUrl = function(base, options, hash) {
  var newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, function(value, key, list) {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
  var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
  var clientId = querystring.unescape(clientCredentials[0]);
  var clientSecret = querystring.unescape(clientCredentials[1]);
  return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function() {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});

