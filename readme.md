# base-auth-jwt
Rest API BASE (Basic Auth social email) this is basic usage for authentication using email, facebook, and google, the database mongodb and using mongoose package

```git clone https://github.com/mzcoder-hub/rest-base-jwt.git```

```cd rest-base-jwt```

then run 

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
