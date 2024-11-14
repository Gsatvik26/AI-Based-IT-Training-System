document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    const message = await response.text();
    document.getElementById('message').innerText = message;

    // If registration is successful, redirect to login page
    if (response.ok) {
        window.location.href = 'login.html';
    } else {
        // Show prompt on the same page if registration fails
        alert('Registration failed: ' + message);
    }
});
