var app = angular.module("satapp", ['satellizer']);

app.config(function($routeProvider, $locationProvider, $authProvider){
  $routeProvider
  .when('/', {
    controller: "mainController",
    template: "templates/index.html"
  })
  .when('/', {
    controller: "loginController",
    template: "templates/login.html"
  })
  .otherwise({redirectTo: '/'});

  $locationProvider.html5Mode(true);
});