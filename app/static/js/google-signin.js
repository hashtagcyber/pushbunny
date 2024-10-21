function handleCredentialResponse(response) {
  // Send the ID token to your server
  fetch('/google_login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({credential: response.credential})
  }).then(res => res.json())
  .then(data => {
    if (data.success) {
      window.location.href = '/dashboard';
    } else {
      alert('Login failed: ' + data.error);
    }
  });
}
