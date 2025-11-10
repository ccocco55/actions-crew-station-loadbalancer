// ===================== 드롭다운(글쓰기/프로필) =====================
const popups = document.querySelectorAll("div.btn-click-slide-container");
const profilePopups = document.querySelectorAll("div.profile-popup-btn");

document.body.addEventListener("click", (e) => {
    if (e.target.closest(".btn-click-slide-container, .profile-popup-btn")) return;

    popups.forEach((el) => el.classList.remove("active"));
    profilePopups.forEach((el) => el.classList.remove("active"));

    const postBtn = e.target.closest("button.post-reg-btn");
    if (postBtn) {
        const scope = postBtn.closest(
            ".member-profile-wrap, .sticky-member-wrap, .login-section, .user-section, .sticky-container"
        );
        scope?.querySelector(".btn-click-slide-container")?.classList.add("active");
        return;
    }

    //  프로필 버튼
    const profileBtn = e.target.closest("button.mebmer-profile-btn");
    if (profileBtn) {
        profileBtn
            .closest(".member-profile-wrap")
            .querySelector(".profile-popup-btn")
            .classList.add("active");
        return;
    }

});

// ===================== 헤더 버튼에 따른 서브 헤더 =====================
let currentPage = "home";
let path = window.location.pathname.split("/")[1]
console.log(path+" asdasd");
if (path === "diaries"){

    console.log("다이어리 들어왔어")
    currentPage = "diary";

} else if(path === "notice") {
    console.log("공지사항")
    currentPage = "notice";
}
const aTag = document.querySelector(`a.sticky-btn.${currentPage}.${currentPage}-btn`);
console.log(aTag);
aTag.classList.add("active");


const stickyBtns = document.querySelectorAll("a.sticky-btn");
stickyBtns.forEach((stickyBtn) => {
    // 헤더 버튼 글씨 색깔 바꿔주기
    // stickyBtns.forEach((btn) => btn.classList.remove("active"));
    // stickyBtn.classList.add("active");

    const subHeader = stickyBtn.classList[1];
    // currentPage = subHeader;
    // console.log(currentPage)

    const headers = document.querySelectorAll(`div.sticky-container.sticky-sub-container`);
    console.log(headers)
    headers.forEach((header) => {
        if (header.classList.contains(currentPage)) {
            header.classList.add("active");
            header.firstElementChild.style.zIndex = 1000;
        } else {
            header.classList.remove("active");
            header.firstElementChild.style.zIndex = 1200;
        }
    });

    // 서브헤더 선택 초기화
    const initActives = document.querySelectorAll(
        `div.sticky-container.sticky-sub-container.${subHeader} a.header-category`
    );
    initActives.forEach((init, index) => {
        if (index === 0) {
            init.classList.add("active");
            init.firstElementChild.firstElementChild.classList.replace("header-name", "header-name-check");
        } else {
            init.classList.remove("active");
            init.firstElementChild.firstElementChild.classList.replace("header-name-check", "header-name");
        }
    });

});

// ===================== 서브 헤더 버튼 클릭 이벤트 =====================
const subHeaders = document.querySelectorAll("div.sticky-container.sticky-sub-container");
subHeaders.forEach((subHeader) => {
    subHeader.addEventListener("click", (e) => {
        const activeBtn = e.target.closest("a.header-category");
        if (!activeBtn) return;

        if (!activeBtn.classList.contains("active")) {
            subHeader.querySelector("a.header-category.active")?.classList.remove("active");
            subHeader.querySelector("p.header-name-check")
                ?.classList.replace("header-name-check", "header-name");

            activeBtn.classList.add("active");
            activeBtn.firstElementChild.firstElementChild
                .classList.replace("header-name", "header-name-check");
        }
    });
});

// ===================== 서브 헤더 호버/아웃 시 노출 제어 =====================
const crewSubHeader = document.querySelector("div.sticky-container.sticky-sub-container.crew");
const diarySubHeader = document.querySelector("div.sticky-container.sticky-sub-container.diary");
let prevBtn = null;

stickyBtns.forEach((stickyBtn) => {
    let subHeader = null;
    stickyBtn.addEventListener("mouseenter", () => {
        const category = stickyBtn.classList[1];
        if (category === "crew") subHeader = crewSubHeader;
        else if (category === "diary") subHeader = diarySubHeader;

        if (subHeader) {
            subHeader.firstElementChild.style.top = "81px";
            subHeader.classList.add("active");
        }
    });

    stickyBtn.addEventListener("mouseleave", () => {
        const category = stickyBtn.classList[1];
        if (currentPage === category) return;

        if (category === "crew") subHeader = crewSubHeader;
        else if (category === "diary") subHeader = diarySubHeader;

        prevBtn = stickyBtn;
        setTimeout(() => {
            if (!stickyBtn.matches(":hover") && !subHeader?.matches(":hover")) {
                subHeader?.classList.remove("active");
                subHeader.firstElementChild.style.top = "29px;";
            }
        }, 100);
    });
});

crewSubHeader?.addEventListener("mouseleave", () => {
    if (currentPage === "crew") return;
    setTimeout(() => {
        if (!prevBtn?.matches(":hover") && !crewSubHeader.matches(":hover")) {
            crewSubHeader.classList.remove("active");
        }
    }, 100);
});

diarySubHeader?.addEventListener("mouseleave", () => {
    if (currentPage === "diary") return;
    setTimeout(() => {
        if (!prevBtn?.matches(":hover") && !diarySubHeader.matches(":hover")) {
            diarySubHeader.classList.remove("active");
        }
    }, 100);
});

// ===================== 스크롤 시 헤더 내려가게 =====================
const header = document.getElementById("header");
const secondaryHeaders = document.querySelectorAll("div.layout-navigation-secondary");

window.addEventListener("wheel", (e) => {
    if (e.wheelDeltaY < 0) {
        secondaryHeaders.forEach((secondaryHeader) => {
            secondaryHeader.classList.add("scroll-down");
            secondaryHeader.style.top = "29px";
        });
    } else {
        secondaryHeaders.forEach((secondaryHeader) => {
            secondaryHeader.classList.remove("scroll-down");
            secondaryHeader.style.top = "81px";
        });
    }
});

// ===================== 서브 카테고리 클릭 시 active 클래스 =====================
let btnCheck = true;
let prevCategory = "total";
const items = document.querySelectorAll(".header-category");

items.forEach((item) => {
    item.addEventListener("click", async (e) => {
        e.preventDefault();
        if (!btnCheck) return;

        if (prevCategory !== item.id) {
            category = item.id;
            page = 1;
        }
        btnCheck = false;

        await showList(page, keyword, orderType, category, prevCategory !== item.id);
        prevCategory = category;

        items.forEach((e) => e.classList.remove("active"));
        item.classList.add("active");

        setTimeout(() => {
            btnCheck = true;
            checkMore = true;
            checkScroll = true;
        }, 1500);
    });
});




// 로그아웃

const logoutLink = document.querySelector("a.logout-btn");

logoutLink.addEventListener("click", async (e) => {
    e.preventDefault();
    await memberService.logout()
    location.href = "/member/login";
});

// 알람 갯수

document.addEventListener("DOMContentLoaded", () => {
    memberService.alarmService.updateCount();
    setInterval(memberService.alarmService.updateCount, 30000);
});








