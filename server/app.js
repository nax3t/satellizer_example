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
