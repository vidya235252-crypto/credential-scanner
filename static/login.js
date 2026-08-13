const loginTab = document.getElementById("loginTab");
const signupTab = document.getElementById("signupTab");
const authForm = document.getElementById("authForm");
const emailInput = document.getElementById("emailInput");
const passwordInput = document.getElementById("passwordInput");
const authSubmitBtn = document.getElementById("authSubmitBtn");
const authStatus = document.getElementById("authStatus");

let mode = "login";

loginTab.addEventListener("click", () => setMode("login"));
signupTab.addEventListener("click", () => setMode("signup"));

function setMode(newMode) {
    mode = newMode;
    loginTab.classList.toggle("active", mode === "login");
    signupTab.classList.toggle("active", mode === "signup");
    authSubmitBtn.textContent = mode === "login" ? "Login" : "Sign Up";
    authStatus.textContent = "";
}

authForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    if (!email || !password) {
        setStatus("Enter both email and password.", "#d29922");
        return;
    }
    authSubmitBtn.disabled = true;
    const endpoint = mode === "login" ? "/auth/login" : "/auth/signup";
    try {
        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || "Authentication failed");
        }
        localStorage.setItem("access_token", data.access_token);
        window.location.href = "/";
    } catch (err) {
        setStatus(err.message, "#f85149");
        authSubmitBtn.disabled = false;
    }
});

function setStatus(message, color) {
    authStatus.textContent = message;
    authStatus.style.color = color;
}