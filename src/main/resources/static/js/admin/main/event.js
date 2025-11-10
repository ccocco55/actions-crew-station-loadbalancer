function showSection(name) {
    closeAllModals();
    const container = document.getElementById('page-container');
    if (!container) return;

    const targetId = `section-${name}`;
    const sections = Array.from(container.querySelectorAll('[id^="section-"]'));
    let target = container.querySelector(`#${CSS.escape(targetId)}`);

    if (!target) {
        return;
    }

    sections.forEach(sec => {
        sec.style.setProperty('display', 'none', 'important');
    });

    target.style.setProperty('display', 'block', 'important');
    target.style.setProperty('visibility', 'visible', 'important');
    target.style.setProperty('opacity', '1', 'important');

    target.querySelectorAll('.tab-view-body, .tab-wrapper, .tab-body')
        .forEach(el => {
            el.style.setProperty('display', 'block', 'important');
            el.style.setProperty('visibility', 'visible', 'important');
            el.style.setProperty('opacity', '1', 'important');
            el.style.setProperty('height', 'auto', 'important');
            el.style.setProperty('max-height', 'none', 'important');
            el.style.setProperty('overflow', 'visible', 'important');
        });

    if (location.hash !== `#${name}`) history.pushState(null, '', `#${name}`);
    document.querySelectorAll('[data-section]').forEach(a => {
        a.classList.toggle('active', a.dataset.section === name);
    });

    if (!showSection.inited) showSection.inited = {};
    const initMap = {
        'home'        : window.mainInit,
        'member'      : window.memberInit,
        'notice'      : window.noticeInit,
        'diary-report': window.diaryReportInit,
        'gift-report' : window.giftReportInit,
        'crew-report' : window.crewReportInit,
        'payment'     : window.paymentInit,
        'inquiry'     : window.inquiryInit,
        'banner'      : window.bannerInit,

    };
    const init = initMap[name];
    if (typeof init === 'function') {
        try { init(); }
        catch (e) { console.error(`[showSection] init error (${name})`, e); }
    }

}

function closeAllModals() {
    document.querySelectorAll('.modal.show, .report-modal.show, .member-modal.show').forEach((m) => {
        m.classList.remove('show');
        m.style.display = 'none';
        m.setAttribute('aria-hidden', 'true');
    });

    // body 클래스도 정리
    document.body.classList.remove('modal-open');
}





   // 사이드바
(() => {
    const side = document.querySelector("#bootpay-side");
    if (!side) return;

    const topButtons = side.querySelectorAll(".menu-item > .menu-btn");
    const subLists   = side.querySelectorAll(".menu-item > .menu-sub-list");

    const openPanel = (btn, panel) => {
        if (!panel) return;
        panel.classList.add("show");
        panel.style.display = "block";
        panel.style.height  = "auto";
        panel.style.overflow = "visible";
        btn.classList.add("active", "current");
        btn.closest("li")?.classList.add("open");
    };

    const closePanel = (panel) => {
        panel.classList.remove("show");
        panel.style.display = "none";
        panel.style.height  = "";
        panel.style.overflow = "";
    };

    const closeAllMenus = () => {
        subLists.forEach(closePanel);
        topButtons.forEach((btn) => btn.classList.remove("active", "current"));
        side.querySelectorAll(".menu-list > li").forEach((li) => li.classList.remove("open"));
    };

    const syncFromDOM = () => {
        subLists.forEach((ul) => {
            const hasActiveChild = !!ul.querySelector(".boot-link.active");
            const hash = (location.hash || "").slice(1);
            const childForHash = ul.querySelector(`.boot-link[data-section="${hash}"]`);
            if (hasActiveChild || childForHash || ul.classList.contains("show")) {
                const btn = ul.previousElementSibling;
                openPanel(btn, ul);
                if (childForHash) childForHash.classList.add('active');
            } else {
                closePanel(ul);
            }
        });
    };
    syncFromDOM();

    side.addEventListener("click", (e) => {
        if (e.target.closest('#filter-status, .bt-pop-menu-context')) return;

        const subLink = e.target.closest(".menu-sub-list .boot-link");
        if (subLink && side.contains(subLink)) {
            e.preventDefault();
            closeAllModals();
            if (subLink.dataset.section) showSection(subLink.dataset.section);

            const ul = subLink.closest(".menu-sub-list");
            ul.querySelectorAll(".boot-link.active").forEach((a) => a.classList.remove("active"));
            subLink.classList.add("active");

            const btn = ul.previousElementSibling;
            openPanel(btn, ul);
            return;
        }

        const btnTop = e.target.closest(".menu-item > .menu-btn");
        if (!btnTop || !side.contains(btnTop)) {
            return;
        }

        if (btnTop.dataset.section) {
            e.preventDefault();
            closeAllModals?.();
            closeAllMenus();
            showSection?.(btnTop.dataset.section);
            btnTop.classList.add("active", "current");
            return;
        }

        e.preventDefault();
        const panel = btnTop.nextElementSibling;
        const hasPane = panel && panel.classList.contains("menu-sub-list");
        if (!hasPane) return;

        const willOpen = !panel.classList.contains("show");
        closeAllMenus();

        if (willOpen) {
            openPanel(btnTop, panel);

            const first = panel.querySelector('.boot-link[data-section]');
            if (first) {
                setTimeout(() => {
                    panel.querySelectorAll('.boot-link.active').forEach(a => a.classList.remove('active'));
                    first.classList.add('active');
                    showSection(first.dataset.section);
                }, 0);
            }
        } else {
            openPanel(btnTop, panel);
            const activeChild = panel.querySelector('.boot-link.active');
            const first = panel.querySelector('.boot-link[data-section]');
            if (!activeChild && first) {
                setTimeout(() => {
                    first.classList.add('active');
                    showSection(first.dataset.section);
                    console.log('[sidebar] reopen route ->', first.dataset.section);
                }, 0);
            }
        }

    });
    window.addEventListener("popstate", syncFromDOM);
})();


   // 우측 상단 유저 메뉴
(() => {
    const initUserMenu = () => {
        const btn  = document.getElementById("userMenuBtn");
        const menu = document.getElementById("userMenu");
        if (!btn || !menu) return;

        const hide = () => {
            menu.classList.remove("show");
            menu.style.display = "none";
            btn.setAttribute("aria-expanded", "false");
        };

        const toggle = () => {
            const willShow = !menu.classList.contains("show");
            menu.classList.toggle("show", willShow);
            menu.style.display = willShow ? "block" : "none";
            btn.setAttribute("aria-expanded", String(willShow));
        };

        btn.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            toggle();
        });

        document.addEventListener("click", (e) => {
            if (e.target.closest('#filter-status, .bt-pop-menu-context')) return;
            if (!btn.contains(e.target) && !menu.contains(e.target)) hide();
        });

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") hide();
        });
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initUserMenu);
    } else {
        initUserMenu();
    }
})();

   // 회원 모달(기존 그대로)
(() => {
    const modal = document.querySelector(".member-modal");
    if (!modal) return;

    const closeBtns = modal.querySelectorAll(".close, .btn-close");
    const table = document.querySelector(".table-layout");
    const dialog = modal.querySelector(".modal-dialog");
    if (dialog) dialog.style.margin = "1.75rem auto";

    const openModal = () => {
        modal.style.display = "block";
        requestAnimationFrame(() => {
            modal.classList.add("show");
            modal.style.background = "rgba(0,0,0,0.5)";
            document.body.classList.add("modal-open");
        });
    };

    const closeModal = () => {
        modal.classList.remove("show");
        document.body.classList.remove("modal-open");
        setTimeout(() => { modal.style.display = "none"; }, 100);
    };

    if (table) {
        table.addEventListener("click", async (e) => {
            const btn = e.target.closest(".member-detail-btn, .action-btn");
            if (!btn) return;

            const memberId = btn.dataset.memberid;
            if (!memberId) return;

            const loading = document.getElementById("loading");
            if (loading) loading.style.display = "block";
            try {
                await memberService.getDetailMember(memberLayout.showMemberDetail, memberId);
                openModal();
            } catch (err) {
                console.error("회원 상세 조회 실패:", err);
            } finally {
                if (loading) loading.style.display = "none";
            }
        });
    }

    closeBtns.forEach((b) => b.addEventListener("click", closeModal));
    modal.addEventListener("click", (e) => {

        if (e.target === modal) closeModal();

    });
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && modal.classList.contains("show")) closeModal();
    });
})();

   // 회원 목록/검색/페이징
const memberMenuBtn       = document.getElementById("memberMenu");
const paginationMember    = document.querySelector(".pagination.bootpay-pagination.member-pagination");
const memberKeywordInput  = document.getElementById("memberKeyword");
const memberKeywordBtn    = document.getElementById("memberKeywordBtn");
const loading             = document.getElementById("loading");

const showMembers = async (page = 1, keyword = "") => {
    if (loading) loading.style.display = "block";
    const res = await memberService.getMembers(memberLayout.showMembers, page, keyword);
    if (loading) loading.style.display = "none";
    return res;
};

if (memberKeywordInput) {
    memberKeywordInput.addEventListener("keydown", async (e) => {
        if (e.key === "Enter") await showMembers(1, memberKeywordInput.value.trim());
    });
}
if (memberKeywordBtn) {
    memberKeywordBtn.addEventListener("click", async () => {
        await showMembers(1, memberKeywordInput?.value.trim() || "");
    });
}
if (memberMenuBtn) {
    memberMenuBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        await showMembers(1, "");
    });
}

document.addEventListener("click", async (e) => {
    const a = e.target.closest(".pagination.bootpay-pagination a.paging");
    if (!a) return;
    e.preventDefault();
    const page = Number(a.dataset.page || 1);
    const keyword = (memberKeywordInput?.value || "").trim();
    await showMembers(page, keyword);
});

/* =========================
   대시보드 차트 (기존 그대로)
========================= */
google.charts.load('current', { packages: ['corechart', 'bar'] });

window.addEventListener('DOMContentLoaded', async () => {
    const staticsData = await mainService.getMain(mainLayout.showMain);
    google.charts.setOnLoadCallback(() => {
        drawJoinChart(staticsData);
        drawPie(staticsData);
    });
});

function drawJoinChart(staticsData) {
    const el = document.getElementById('join_chart');
    if (!el) return;
    const dataArray = [['월', '가입자 수']];
    if (Array.isArray(staticsData?.monthlyJoins)) {
        staticsData.monthlyJoins.forEach(m => dataArray.push([m.date, Number(m.count)]));
    }
    const data = google.visualization.arrayToDataTable(dataArray);
    const options = {
        title: '최근 3개월 가입자 수',
        vAxis: { minValue: 0 },
        legend: { position: 'none' },
        colors: ['#3366cc'],
        chartArea: { width: '85%', height: '70%' },
    };
    const chart = new google.visualization.ColumnChart(el);
    chart.draw(data, options);
}

function drawPie(staticsData) {
    const el = document.getElementById('piechart');
    if (!el) return;
    const dataArray = [['지역', '비율']];
    if (Array.isArray(staticsData?.popularCountries)) {
        staticsData.popularCountries.forEach(c => dataArray.push([c.country, Number(c.count)]));
    }
    const data = google.visualization.arrayToDataTable(dataArray);
    const options = {
        title: '인기 여행지 TOP 5',
        pieHole: 0.4,
        legend: { position: 'bottom' },
        chartArea: { width: '90%', height: '80%' },
    };
    const chart = new google.visualization.PieChart(el);
    chart.draw(data, options);
}

  // 로그인 정보/로그아웃
async function fetchWithRefresh(url, opts = {}) {
    let res = await fetch(url, { ...opts, credentials: 'include' });
    if (res.status === 401) {
        const r = await fetch('/api/admin/auth/refresh', { method: 'GET', credentials: 'include' });
        if (r.ok) res = await fetch(url, { ...opts, credentials: 'include' });
    }
    return res;
}

(async () => {
    try {
        const res = await fetchWithRefresh('/api/admin/auth/info');
        if (!res.ok) throw new Error('unauthorized');

        const me = await res.json();

        const emailEl = document.querySelector('.user-menu-email');
        if (emailEl) emailEl.textContent = me.memberEmail || '관리자';

        const avatarEl = document.querySelector('.user-avatar');
        if (avatarEl) {
            const letter = (me.memberEmail || 'C').trim().charAt(0).toUpperCase();
            avatarEl.textContent = letter || 'C';
        }
    } catch (e) {
        window.location.href = '/admin/login';
    }
})();

(function attachLogout() {
    const logoutLink = document.getElementById('logout-link');
    if (!logoutLink) return;
    logoutLink.addEventListener('click', async (e) => {
        e.preventDefault();
        try { await fetch('/api/admin/auth/logout', { method: 'POST', credentials: 'include' }); }
        finally { window.location.href = '/admin/login'; }
    });
})();


window.addEventListener('DOMContentLoaded', () => {
    const initial = (location.hash || '#home').slice(1);
    showSection(initial);
});
window.addEventListener('popstate', () => {
    const name = (location.hash || '#home').slice(1);
    showSection(name);
});
