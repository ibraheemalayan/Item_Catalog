window.fbAsyncInit = function() {
  FB.init({
    appId      : '794962974270590',
    cookie     : true,                     // Enable cookies to allow the server to access the session.
    xfbml      : true,                     // Parse social plugins on this webpage.
    version    : 'v5.0'           // Use this Graph API version for this call.
  });

}

function sendTokenToServer(access_token) {
    console.log(access_token)
    console.log('Welcome!  Fetching your information.... ');
    FB.api('/me', function(response) {
      console.log('Successful login for: ' + response.name);
     $.ajax({
      type: 'POST',
      url: '/fbconnect?state='+getCookie('state'),
      processData: false,
      data: access_token,
      contentType: 'application/octet-stream; charset=utf-8',
      success: function(result) {
        // Handle or verify the server response if necessary.
        if (result) {
          $('#result').html('Login Successful!</br>'+ result + '</br>Redirecting...')
         setTimeout(function() {
          window.location.href = "/";
         }, 4000);

      } else {
        $('#result').html('Failed to make a server-side call. Check your configuration and console.');
         }
      }

      });
    });
  }

  function getCookie(cname) {
  var name = cname + "=";
  var decodedCookie = decodeURIComponent(document.cookie);
  var ca = decodedCookie.split(';');
  for(var i = 0; i <ca.length; i++) {
    var c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
  }

function fb_login(){
    FB.login(function(response) {

        if (response.authResponse) {
            console.log('Welcome!  Fetching your information.... ');
            //console.log(response); // dump complete info
            access_token = response.authResponse.accessToken; //get access token
            user_id = response.authResponse.userID; //get FB UID

            sendTokenToServer(access_token)
        } else {
            //user hit cancel button
            console.log('User cancelled login or did not fully authorize.');

        }
    }, {
        scope: 'public_profile,email'
    });
}
(function() {
    var e = document.createElement('script');
    e.src = document.location.protocol + '//connect.facebook.net/en_US/all.js';
    e.async = true;
    document.body.appendChild(e);
}());
