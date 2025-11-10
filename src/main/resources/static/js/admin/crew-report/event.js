const tabs = document.querySelectorAll(".report-tabs .tab-switch");
const getRows = () => document.querySelectorAll("table.table-reports tbody tr");


const normalizeType = (t) => {
    const value = String(t || "").trim().toLowerCase();
    return value === "short" ? "short" : "long";
};

const applyFilter = (typeRaw) => {
    const type = normalizeType(typeRaw);
    tabs.forEach((t) =>
        t.classList.toggle("active", normalizeType(t.dataset.type) === type)
    );
    getRows().forEach((r) => {
        r.style.display = normalizeType(r.dataset.type) === type ? "" : "none";
    });
};

// 새로고침해도 유지
const getInitType = () => {
    const qs = new URLSearchParams(location.search).get("type");
    const ls = localStorage.getItem("reportType");
    return normalizeType(qs || ls || "long");
};

const setInitType = (type) => {
    localStorage.setItem("reportType", type);
    const p = new URLSearchParams(location.search);
    p.set("type", type);
    history.replaceState(null, "", `${location.pathname}?${p.toString()}`);
};

// 초기 적용
document.addEventListener("DOMContentLoaded", async () => {
    const initType = getInitType();
    applyFilter(initType);

    const items = await crewReportService.getCrewReport(0, initType.toUpperCase());
    crewReportLayout.list(items);

    const tbody = document.querySelector("#registerCrewReportList");
    tbody.addEventListener("click", (e) => {
        const btn = e.target.closest(".action-btn.view, .mdi-chevron-right");
        if (!btn) return;
        const tr = btn.closest("tr");
        const reportId = btn.dataset.id || tr.dataset.id;
        if (!reportId) return;
        crewReportLayout.openModal(tr, reportId);
    });
});


// 탭 클릭
tabs.forEach((tab) => {
    tab.addEventListener("click", async () => {
        const type = tab.dataset.type;
        applyFilter(type);
        setInitType(type);
        const items = await crewReportService.getCrewReport(0, type.toUpperCase());
        crewReportLayout.list(items);
    });
});

window.addEventListener("popstate", () => {
    applyFilter(getInitType());
});


