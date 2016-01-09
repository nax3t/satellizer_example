var mongoose = require("mongoose");
mongoose.connect("mongodb://localhost/satauth");
mongoose.set("debug",true);

module.exports.User = require("./user");