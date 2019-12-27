# rest-node-base-jwt
Rest API BASE (Basic Auth social email) this is basic usage for authentication using email, facebook, and google, the database mongodb and using mongoose package

```git clone https://github.com/mzcoder-hub/rest-base-jwt.git```

```cd rest-base-jwt```

# Config Global variable
you can change the database string and the other ClientID and Client Secret the social media on the config > default.json
```
 {
	"mongoURI": "mongodb://localhost:27017/snackers",
	"jwtSecret": "ThisisSecret",
	"clientID": "YOUR_FACEBOOK_CLIENT_ID_HERE",
	"clientSecret": "YOUR_FACEBOOK_CLIENT_SECRET_HERE",
	"callbackURL": "http://localhost:5000/api/auth/facebook/callback",
	"clientIDGoogle": "YOUR_GOOGLE_CLIENT_ID_HERE",
	"clientSecretGoogle": "YOUR_GOOGLE_CLIENT_SECRET_HERE",
	"callbackGoogleUrl": "http://localhost:5000/api/auth/google/callback"
}
```
#### Note: you can change the callback but you should change the route at route > api folder ####

to install dependency u can run this command

```npm install```

# The Route
### Register via Email

``` http://localhost:5000/api/auth/email/register ```

required method POST and the request should be 

``` 
{
  "name" : "Your Name ",
  "email" : "your email",
  "password" : "your password"
}
```

### Login via Email

``` http://localhost:5000/api/auth/email ```

required method POST and the request should be 

``` 
{
  "email" : "your email",
  "password" : "your password"
}
```

### Login and register using facebook

``` http://localhost:5000/api/auth/facebook ```

Require Method get will be redirect to facebook and get token on

``` http://localhost:5000/api/auth/facebook/accessToken ```

### Login and register using Google

``` http://localhost:5000/api/auth/google ```

Require Method get will be redirect to Google and get token on

``` http://localhost:5000/api/auth/google/accessToken ```

### Email Reset Link Setting ###
the email service i have created that using the sendgrid web API email. you can register free at sendgrid.com

and change the API in cofig > default.json folder
