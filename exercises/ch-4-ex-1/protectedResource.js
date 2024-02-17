let express = require("express");
let bodyParser = require('body-parser');
let cons = require('consolidate');
let nosql = require('nosql').load('database.nosql');
let __ = require('underscore');
let cors = require('cors');

let app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

let resource = {
  "name": "Protected Resource",
  "description": "This data has been protected by OAuth 2.0"
};

let getAccessToken = function(req, res, next) {
  let inToken = null;
  let auth = req.headers['authorization'];
  if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
    inToken = auth.slice('bearer '.length);
  } else if (req.body && req.body.access_token) {
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }

  if (!inToken) {
    res.status(401).end();
    return;
  }

  console.log('Incoming token: %s', inToken);

  // NOTE: I find it weird that the protected resource is getting the token from the authorization server's 
  // database. I would expect the protected resource to have to communicate with the authorization server to 
  // validate the token and get the authorization scopes. I'm not sure if this is what really happens in 
  // production systems like Auth0, Okta, etc.

  // Validate the token 
  nosql.one().make(function(builder) {
    builder.where('access_token', inToken);
    builder.callback(function(err, token) {
      if (token) {
        console.log("We found a matching token: %s", inToken);
      } else {
        console.log('No matching token was found.');
      };
      req.access_token = token;
      next();
      return;
    });
  });
};

// Protect all routes through middleware that checks for the access token
app.all('*', getAccessToken);

app.options('/resource', cors());

app.post("/resource", cors(), function(req, res) {
  if (!req.access_token) {
    res.status(401).end();
    return;
  }

  res.json(resource);
});

let server = app.listen(9002, 'localhost', function() {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

