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

// GET /api/admin/stats (pakai credentials=include supaya cookie ACCESS_TOKEN ikut)
document.getElementById("btnAdminStat").onclick = async () => {
    try {
        const r = await fetch(`${API}/api/admin/stats`, { credentials: "include" });
        if (!r.ok) return out(`HTTP ${r.status}`);
        out(await r.json());
    } catch (e) {
        out(String(e));
    }
};

// GET /api/admin/stats (pakai credentials=include supaya cookie ACCESS_TOKEN ikut)
document.getElementById("btnUser").onclick = async () => {
    try {
        const r = await fetch(`${API}/api/users/c1e715e9-1b22-452b-9a2c-ff122f109716`, { credentials: "include" });
        if (!r.ok) return out(`HTTP ${r.status}`);
        out(await r.json());
    } catch (e) {
        out(String(e));
    }
};

document.getElementById("btnListDevice").onclick = async () => {
    try {
        const r = await fetch(`${API}/api/devices`, { credentials: "include" });
        if (!r.ok) return out(`HTTP ${r.status}`);
        out(await r.json());
    } catch (e) {
        out(String(e));
    }
};