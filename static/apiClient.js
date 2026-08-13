async function authFetch(url, options = {}) {
    const token = localStorage.getItem("access_token");
    const headers = {
        ...(options.headers || {}),
        "Authorization": `Bearer ${token}`
    };
    const response = await fetch(url, { ...options, headers });
    if (response.status === 401) {
        localStorage.removeItem("access_token");
        window.location.href = "/login";
        throw new Error("Session expired");
    }
    return response;
}