const API = "http://localhost:8080";

const out = (x) => (document.getElementById("out").textContent =
    typeof x === "string" ? x : JSON.stringify(x, null, 2));

// GET /api/me (pakai credentials=include supaya cookie ACCESS_TOKEN ikut)
document.getElementById("btnMe").onclick = async () => {
    try {
        const r = await fetch(`${API}/api/me`, { credentials: "include" });
        if (!r.ok) return out(`HTTP ${r.status}`);
        out(await r.json());
    } catch (e) {
        out(String(e));
    }
};

// POST /api/auth/logout (revoke jti + hapus cookie)
document.getElementById("btnLogout").onclick = async () => {
    try {
        const r = await fetch(`${API}/api/auth/logout`, {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" }
        });
        out(await r.json());
    } catch (e) {
        out(String(e));
    }
};

// POST /api/auth/logout (revoke jti + hapus cookie)
document.getElementById("btnRefresh").onclick = async () => {
    try {
        const r = await fetch(`${API}/api/auth/refresh`, {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" }
        });
        out(await r.json());
    } catch (e) {
        out(String(e));
    }
};
