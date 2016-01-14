# Satellizer Example

Structure your app as follows:

```
app_name
--client
----js
------templates
--------index.html
--------login.html
--------signup.html
------app.js
------controllers.js
----index.html
--server
----models
----routes
----app.js
--.gitignore
--.env
--package.json
```
Before you initialize git, add the following to your `.gitignore`:
```
node_modules
.env
```

Now begin with your `server`. Add the following packages to your `package.json`:

```js
"dependencies": {
   "bcrypt": "^0.8.5",
   "body-parser": "^1.14.2",
   "dotenv": "^1.2.0",
   "express": "^4.13.3",
   "jsonwebtoken": "^5.5.4",
   "moment": "^2.11.0",
   "mongoose": "^4.3.4",
   "morgan": "^1.6.1",
   "request": "^2.67.0"
 }
```

Let's build out our `app.js` on the backend:

```js
require("dotenv").load();

var express = require("express"),
    app = express(),
    morgan = require("morgan"),
    bodyParser = require("body-parser"),
    path = require("path"),
    routes = require('./routes');

app.use(morgan("tiny"));
app.use(bodyParser.json());

app.use('/css',express.static(path.join(__dirname, '../client/css')));
app.use('/js',express.static(path.join(__dirname, '../client/js')));
app.use('/templates',express.static(path.join(__dirname, '../client/js/templates')));

app.use('/api/users', routes.users);
app.use('/api/auth', routes.auth);

app.get('*', function(req, res) {
  res.sendFile(path.join(__dirname, '../client', 'index.html'));
});

app.listen(3000, function(){
  console.log("Server is listening on port 3000");
});
```

Now let's create some routes, open up `auth.js` inside of your `routes` folder and add:

```js
var express = require("express");
var router = express.Router();
var request = require("request");
var db = require('../models/');
var jwt = require('jsonwebtoken');
var moment = require('moment');

/*
 |--------------------------------------------------------------------------
 | Generate JSON Web Token
 |--------------------------------------------------------------------------
 */
function createJWT(user) {
  var payload = {
    sub: user._id,
    iat: moment().unix(),
    exp: moment().add(14, 'days').unix()
  };

  return jwt.sign(payload, process.env.JWT_SECRET);
}

router.post('/facebook', function(req, res) {
    var fields = ['id', 'email', 'first_name', 'last_name', 'link', 'name'];
    var accessTokenUrl = 'https://graph.facebook.com/v2.5/oauth/access_token';
    var graphApiUrl = 'https://graph.facebook.com/v2.5/me?fields=' + fields.join(',');
    var params = {
      code: req.body.code,
      client_id: req.body.clientId,
      client_secret: process.env.FACEBOOK_SECRET,
      redirect_uri: req.body.redirectUri
    };

    // Step 1. Exchange authorization code for access token.
    request.get({ url: accessTokenUrl, qs: params, json: true }, function(err, response, accessToken) {
      if (response.statusCode !== 200) {
        return res.status(500).send({ message: accessToken.error.message });
      }

      // Step 2. Retrieve profile information about the current user.
      request.get({ url: graphApiUrl, qs: accessToken, json: true }, function(err, response, profile) {
        if (response.statusCode !== 200) {
          return res.status(500).send({ message: profile.error.message });
        }
        if (req.headers.authorization) {
          db.User.findOne({ facebook: profile.id }, function(err, existingUser) {
            if (existingUser) {
              return res.status(409).send({ message: 'There is already a Facebook account that belongs to you' });
            }
            var token = req.headers.authorization.split(' ')[1];
            var payload = jwt.verify(token, process.env.JWT_SECRET);
            db.User.findById(payload.sub, function(err, user) {
              if (!user) {
                return res.status(400).send({ message: 'User not found' });
              }
              user.facebook = profile.id;
              user.picture = user.picture || 'https://graph.facebook.com/v2.3/' + profile.id + '/picture?type=large';
              user.displayName = user.displayName || profile.name;
              user.save(function() {
                var token = createJWT(user);
                res.send({ token: token });
              });
            });
          });
        } else {
          // Step 3b. Create a new user account or return an existing one.
          db.User.findOne({ facebook: profile.id }, function(err, existingUser) {
            if (existingUser) {
              var token = createJWT(existingUser);
              return res.send({ token: token });
            }
            var user = new db.User();
            user.facebook = profile.id;
            user.picture = 'https://graph.facebook.com/' + profile.id + '/picture?type=large';
            user.displayName = profile.name;
            user.save(function() {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        }
      });
    });
});

module.exports = router;
```

Now open `users.js` and add:

```js
var express = require("express");
var router = express.Router();

router.get('/', function(req,res){
  res.send("nice!");
});

module.exports = router;
```

There's nothing there now, but you can use it later if you want to add some user routes.

To finish off the routes, open `index.js` from inside of `routes` and add:

```js
module.exports = {
  users: require("./users"),
  auth: require("./auth")
};
```

Boom! Let's move onto our model now.

Open up `user.js` from `models` and add:

```js
var mongoose = require("mongoose");
var bcrypt = require("bcrypt");

var userSchema = new mongoose.Schema({
  email: { type: String, unique: true, lowercase: true },
  password: { type: String, select: false },
  displayName: String,
  picture: String,
  facebook: String,
});

userSchema.pre('save', function(next) {
  var user = this;
  if (!user.isModified('password')) {
    return next();
  }
  bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(user.password, salt, function(err, hash) {
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(password, done) {
  bcrypt.compare(password, this.password, function(err, isMatch) {
    done(err, isMatch);
  });
};

var User = mongoose.model('User', userSchema);

module.exports = User;
```

Now open `index.js` from the same folder and add:

```js
var mongoose = require("mongoose");
mongoose.connect("mongodb://localhost/satauth");
mongoose.set("debug",true);

module.exports.User = require("./user");
```

Awesome, now we can work on the client (angular) side of the app.

Open up `index.html` from the `client` folder and add: 

```html
<!DOCTYPE html>
<html lang="en" ng-app="satapp">
<head>
  <meta charset="UTF-8">
  <title>Document</title>
  <base href="/">
</head>
<body>
  <div ng-view>
  </div>
  <script src="http://ajax.googleapis.com/ajax/libs/angularjs/1.4.5/angular.js"></script>
  <script src="http://ajax.googleapis.com/ajax/libs/angularjs/1.4.5/angular-route.js"></script>
  <script src="http://cdn.jsdelivr.net/satellizer/0.13.3/satellizer.min.js"></script>
  <script src="js/app.js"></script>
  <script src="js/controllers.js"></script>
</body>
</html>
```

Now open `app.js` from the `js` folder and add:

```js
var app = angular.module("satapp", ['ngRoute','satellizer']);

app.config(function($routeProvider, $locationProvider, $authProvider){
  $routeProvider
  .when('/home', {
    controller: "MainController",
    templateUrl: "templates/index.html",
    resolve: {
      loginRequired: loginRequired
    }
  })
  .when('/', {
    controller: "LoginController",
    templateUrl: "templates/login.html",
    resolve: {
      skipIfLoggedIn: skipIfLoggedIn
    }
  })
  .when('/signup', {
    controller: "SignupController",
    templateUrl: "templates/login.html",
    resolve: {
      skipIfLoggedIn: skipIfLoggedIn
    }
  })
  .when('/logout', {
    template: null,
    controller: 'LogoutController'
  })
  .otherwise({redirectTo:'/'});

  $locationProvider.html5Mode(true);

  $authProvider.facebook({
    clientId: '297860257039585',
    url: '/api/auth/facebook'
  });

  function skipIfLoggedIn($q, $auth, $location) {
      var deferred = $q.defer();
      if ($auth.isAuthenticated()) {
        $location.path('/home');
        deferred.reject();
      } else {
        deferred.resolve();
      }
      return deferred.promise;
    }

    function loginRequired($q, $location, $auth) {
      var deferred = $q.defer();
      if ($auth.isAuthenticated()) {
        deferred.resolve();
      } else {
        $location.path('/');
      }
      return deferred.promise;
    }
});
```
**Be sure to change the `clientId: '297860257039585'` line to use your clientID from the [facebook API](https://developers.facebook.com/).**

Great, now open up the `controllers.js` file and add:

```js
app.controller("MainController", function(){

});

app.controller("LoginController", function($scope, $auth, $location){
  $scope.authenticate = function(provider) {
    $auth.authenticate(provider)
      .then(function() {
        console.log('You have successfully signed in with ' + provider + '!');
        $location.path('/home');
      })
      .catch(function(error) {
        if (error.error) {
          // Popup error - invalid redirect_uri, pressed cancel button, etc.
          console.log(error.error);
        } else if (error.data) {
          // HTTP response error from server
          console.log(error.data.message, error.status);
        } else {
          console.log(error);
        }
      });
  };
});


app.controller('LogoutController', function($location, $auth) {
    if (!$auth.isAuthenticated()) { return; }
    $auth.logout()
      .then(function() {
        console.log('You have been logged out');
        $location.path('/');
      });
  });


app.controller('SignupController', function($scope, $location, $auth) {
    $scope.signup = function() {
      $auth.signup($scope.user)
        .then(function(response) {
          $auth.setToken(response);
          $location.path('/');
          console.log('You have successfully created a new account and have been signed-in');
        })
        .catch(function(response) {
          console.log(response.data.message);
        });
    };
  });
```

Now let's fill out our `templates` with some basic html so we can login.

Open `index.html` from the `templates` folder and add:

```html
<h1>Logged in!</h1>

<a href="/logout">Logout</a>
```

Open `login.html` and add:

```html
<h1>Hi!</h1>

<button ng-click="authenticate('facebook')">Sign in with Facebook</button>
```

Open `signup.html` and add:

```html
<h1>Hi!</h1>

<button ng-click="authenticate('facebook')">Sign up with Facebook</button>
```

Great! You're almost finished, the last step is to get your API secret and clientID from the [facebook API](https://developers.facebook.com/) and configure your app to use it. You should've already added the clientID to `client -> js -> app.js`, if you haven't then go and do that now.

Now open up the `.env` file you made earlier and add:

```
JWT_SECRET=anything_you_want_here
FACEBOOK_SECRET=your_facebook_secret_here
```

Be sure to update the FACEBOOK_SECRET with your own secret key from the facebook developer console.

All set! Run mongod in a separate tab and fire up your server with nodemon. You should now be able to authenticate with facebook!

This is a pretty basic setup, [satellizer](https://github.com/sahat/satellizer) has further documentation for configuring other strategies (e.g., google, github, twitter).

Also, if you need a refresher on JWT's. Check out this [video](http://jwt.io/introduction/)
