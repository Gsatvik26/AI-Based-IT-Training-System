document.getElementById("loginForm").addEventListener("submit", function (event) {
    event.preventDefault();
    
    const username = document.getElementById("loginUsername").value;
    const password = document.getElementById("loginPassword").value;
    const role = document.querySelector('input[name="role"]:checked').value;
    
    // Display message based on role selection (User or Admin)
    if (role === "user") {
        // User login logic here
        document.getElementById("loginMessage").textContent = "User login in progress...";
        // Add actual authentication logic for users here
    } else if (role === "admin") {
        // Admin login logic here
        document.getElementById("loginMessage").textContent = "Admin login in progress...";
        // Add actual authentication logic for admins here
    }
});
