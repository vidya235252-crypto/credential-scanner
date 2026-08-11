(function () {
    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
    }
    const savedTheme = localStorage.getItem("theme") || "dark";
    applyTheme(savedTheme);

    document.addEventListener("DOMContentLoaded", function () {
        const toggleBtn = document.getElementById("themeToggle");
        if (!toggleBtn) {
            return;
        }

        function updateIcon() {
            const current = document.documentElement.getAttribute("data-theme") || "dark";
            toggleBtn.innerHTML = current === "dark"
                ? '<i class="fa-solid fa-moon"></i>'
                : '<i class="fa-solid fa-sun"></i>';
        }

        toggleBtn.addEventListener("click", function () {
            const current = document.documentElement.getAttribute("data-theme") || "dark";
            const next = current === "dark" ? "light" : "dark";
            applyTheme(next);
            localStorage.setItem("theme", next);
            updateIcon();
        });

        updateIcon();
    });
})();
