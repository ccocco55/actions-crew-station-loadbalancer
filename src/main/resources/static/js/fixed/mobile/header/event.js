// document.querySelector(".sticky-action-btn").style.visibility = "hidden";
// document.querySelector(".sticky-action-btn").style.display = "none";
if (window.location.href.includes("detail")) {
    document.querySelector("div.sticky-search-wrap").style.width = "auto";
}else{
    document.querySelector(".sticky-action-btn a").style.display="none";
}
document.querySelector(".sticky-action-btn").style.display = "flex";

document.querySelector(".sticky-action-btn a").addEventListener("click",(e)=>{
    history.back();
})


// 서브헤더 클릭 이벤트
const subHeaders = document.querySelectorAll(
    "div.sticky-container.sticky-sub-container"
);
// 서브헤더 카테고리 클릭 시 색상 바뀌게 만들어주기
subHeaders.forEach((subHeader) => {
    subHeader.addEventListener("click", (e) => {
        console.log(subHeader);

        const activeLink = e.target.closest("a.item-link.navigation-item-link");
        if (activeLink) {
            const aLinks = subHeader.querySelectorAll(
                "a.item-link.navigation-item-link"
            );
            aLinks.forEach((aLink) => {
                aLink.classList.remove("active");
            });
            activeLink.classList.add("active");
        }
    });
});

// 스크롤 이벤트
const header = document.getElementById("header");
const secondaryHeaders = document.querySelectorAll(
    "div.layout-navigation-secondary"
);
// 휠 이벤트 위로 올리면 서브 헤더 보이고 아래로 내리면 서브 헤더 숨기기
window.addEventListener("wheel", (e) => {
    if (e.wheelDeltaY < 0) {
        secondaryHeaders.forEach((secondaryHeader) => {
            console.log(secondaryHeader);
            secondaryHeader.classList.add("scroll-down");
        });
    } else {
        secondaryHeaders.forEach((secondaryHeader) => {
            secondaryHeader.classList.remove("scroll-down");
        });
    }
});

// 검색 아이콘 클릭 이벤트
const searchIcon = document.querySelector("button.search-icon"); // 돋보기 아이콘
const searchModal = document.querySelector("div.search-icon-modal"); // 검색 모달
const closeSearchModal = document.querySelector("button.search-cancle"); // 취소 버튼
// 모달 열기
searchIcon.addEventListener("click", (e) => {
    !searchModal.classList.contains("open") &&
        searchModal.classList.add("open");
});
// 취소 버튼 클릭
closeSearchModal.addEventListener("click", (e) => {
    searchModal.classList.contains("open") &&
        searchModal.classList.remove("open");
});

// 메뉴 리스트에서 버튼 클릭 이벤트
const menuBtns = document.querySelectorAll("button.menu-item-btn"); // 대 카테고리 버튼들
const crewBtn = document.querySelector("div.menu-list-crew"); // 크루 버튼
const diaryBtn = document.querySelector("div.menu-list-diary"); // 다이어리 버튼
let clickCheck = document.querySelector("button.menu-item-btn.gift"); // 우리가 기프트만 모바일이여서 초기 선택된 버튼 설정해주기 및 이전에 변경한 부분 저장
menuBtns.forEach((menuBtn) => {
    menuBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        console.log("큰 메뉴 버튼 클릭하기");
        console.log(clickCheck);
        if (clickCheck) {
            // clickCheck.removeAttribute("style");
            clickCheck.lastElementChild.classList.remove("active"); // 이전에 활성화된 부분 제거하기
        }

        if (clickCheck === menuBtn) {
            // 같은 곳 클릭해도 소카테고리 영역 닫아주기
            menuBtn.nextElementSibling &&
                (menuBtn.nextElementSibling.style.height = "0px");
            clickCheck = null;
            return;
        }

        console.log(clickCheck);
        menuBtn.lastElementChild.classList.add("active"); // 화살표 방향 바꿔주기
        if (menuBtn.classList.contains("crew")) {
            // 크루 버튼 클릭시
            crewBtn.style.height = "172px"; // 소카테고리 보여주기
            diaryBtn.style.height = "0px"; // 다이어리 소카테고리는 닫아주기

        } else if (menuBtn.classList.contains("diary")) {
            // 다이어리 버튼 클릭 시
            diaryBtn.style.height = "129px"; // 다이어리 소카테고리 보여주기

            crewBtn.style.height = "0px"; // 크루 소카테고리 닫아주기
        } else {
            // 그 외 버튼
            document.querySelector("div.product-list-wrapper").style.marginTop= "50px";
            // crewBtn.style.height = "0px"; // 보이는 크루 소카부분들 다 닫아주기
            clickCheck.removeAttribute("style"); // 선택된 영역 없애주기 (배경색 다시 흰색으로)
            modalDown.classList.remove("open"); // 모달 닫아주기 소카 있는 부분은 소카 눌러야 닫기 밑에서 해결
            subCategories[0].style.top = "-41px"; // 밖에 소카 닫아주기
            subCategories[1].style.top = "-41px"; // 밖에 소카 닫아죽
            diaryBtn.style.height = "0px"; // 보이는 다이어리 소카 닫아주기
            menuBtn.style.backgroundColor = "rgb(247, 249, 250)"; // 활성화된 부분 표시해주기
        }
        clickCheck = menuBtn; // 변경된 부분 저장해놓기
    });
});

const detailBtns = document.querySelectorAll("li.detail-link-item"); // 소카부분 버튼들
const subCategories = document.querySelectorAll("div.sub"); // 서브 헤더 부분들
let clickDetailBtn = null; // 변경사항 저장해놓기
detailBtns.forEach((detailBtn) => {
    // 소카 버튼에 클릭 이벤트 넣어놓기
    detailBtn.addEventListener("click", (e) => {
        e.stopPropagation(); // 버블링 막기 (자식 클릭하면 부모도 클릭되는 현상 막기)
        console.log(detailBtn);

        console.log(clickDetailBtn);
        if (clickDetailBtn) {
            // 초기인지 아닌지 체크
            console.log(clickDetailBtn);
            clickDetailBtn.removeAttribute("style"); // 이전에 선택된 소카에 활성화 제거하기
            console.log(detailBtn);
        }
        menuBtns.forEach((menuBtn) => {
            if (menuBtn.hasAttribute("style")) {
                menuBtn.removeAttribute("style"); // 만약 기프트를 선택하고 다이어리에서 소카를 선택하면 기프트 활성화 없애주기
            }
        });

        modalDown.classList.remove("open"); // 모달 닫기
        clickDetailBtn = detailBtn; // 변경사항 수정하기
        const target = e.target.closest("li.menu-item-wrap"); // li 자식들 클릭해도 li로 잡히게 만들기
        console.log(target.firstElementChild);

        target.firstElementChild.style.backgroundColor = "rgb(247, 249, 250)"; // 클릭한 대카 활성화해주기

        console.log(target.firstElementChild.nextElementSibling);

        target.firstElementChild.lastElementChild.classList.remove("active"); // 화살표 방향 바꿔주기
        if (target.firstElementChild.nextElementSibling.hasAttribute("style")) {
            //소카가 열려 있는지 확인
            target.firstElementChild.nextElementSibling.style.height = "0px"; // 소카 열려있으면 닫아주기
        }
        detailBtn.style.backgroundColor = "rgb(247, 249, 250)"; // 소카 버튼에 활성화 해주기
        const category = target.firstElementChild.classList[1]; // 어떤 대카에 소카를 골랐는지 crew, diary 구분해주기
        console.log(category);

        let subHeader = null; // 어디 부분 소카 표시해야하는지 저장해주기
        if (category === "crew") {
            // 크루 소카 클릭 시
            subHeader = subCategories[0];
            subCategories[0].style.top = "51px"; // 모달 밖 크루 소카 보여주기
            subCategories[1].style.top = "-41px"; // 모달 밖 다이어리 소카 닫아주기
            document.querySelector("div.product-list-wrapper").style.marginTop= "90px";
        } else if (category === "diary") {
            // 다이어리 클릭 시
            subHeader = subCategories[1];
            document.querySelector("div.product-list-wrapper").style.marginTop= "90px";
            subCategories[0].style.top = "-41px"; // 모달 밖 크루 소카 닫아주기
            subCategories[1].style.top = "51px"; // 모달 밖 다이어리 소카 보여주기
        }
        // 메뉴 버튼에 누른 소카에 해당하는 서브 헤더에서 클릭한 해당 부분 밖에서도 표시해주기
        subHeader.querySelectorAll("a.navigation-item-link").forEach((a) => {
            if (a.classList.contains("active")) {
                // 이미 체크된 부분은 제거해주기
                a.classList.remove("active");
                console.log(a.textContent.trim());
            } else {
                console.log("작은 메뉴 클릭");
                console.log(
                    a.textContent.trim() === detailBtn.textContent.trim()
                );
            }
            // 글 내용으로 활성화 체크
            a.textContent.trim() === detailBtn.textContent.trim() &&
                a.classList.add("active");
        });
    });
});

// 메뉴 모달 열기
const modalUp = document.querySelector("button.list-action-btn");
modalUp.addEventListener("click", (e) => {
    modalDown.classList.add("open");
});
// 메뉴 모달 닫기
const modalDown = document.querySelector("div.menu-list-modal");
modalDown.addEventListener("click", (e) => {
    console.log("모달 닫기");

    modalDown.classList.remove("open");
});

// 로그아웃

const logoutLink = document.querySelector("a.logout-menu-footer");

logoutLink.addEventListener("click", async (e) => {
    e.preventDefault();
    console.log("fsdfdssafsdfsdfsdfasdfdfdfdfddsfsd")
    await memberService.logout()
    location.href = "/mobile/login";
});


const menuModal = document.querySelector('.menu-list-modal');
if (menuModal) {
    const profileWrap   = menuModal.querySelector('.login-profile-wrap');       // 로그인 전용
    const profileImgEl  = profileWrap ? profileWrap.querySelector('img') : null;
    const profileNameEl = profileWrap ? profileWrap.querySelector('p')   : null;
    const profileImg = document.querySelector('.login-profile-wrap img');

    const guestWrap     = menuModal.querySelector('.login-logout-container');   // 비로그인 전용
    const logoutLink    = menuModal.querySelector('.logout-menu-footer');       // 로그아웃 링크

    // 기본 상태: 비로그인
    if (profileWrap) profileWrap.style.display = 'none';
    if (guestWrap)   guestWrap.style.display   = '';
    if (logoutLink)  logoutLink.style.display  = 'none';

    // 로그인 정보 불러오기
    memberService.info(async (member) => {
        console.log("로그인 정인정보")
        if (!member) {
            // 비로그인 유지
            if (profileWrap) profileWrap.style.display = 'none';
            if (guestWrap)   guestWrap.style.display   = '';
            if (logoutLink)  logoutLink.style.display  = 'none';
            return;
        }

        // 로그인 상태
        if (guestWrap)   guestWrap.style.display   = 'none';
        if (profileWrap) profileWrap.style.display = '';
        if (logoutLink)  logoutLink.style.display  = '';

        // 프로필가져오기
        memberService.info(async (member) => {
            if (!member) return;
            const id = member.id;
            let imgUrl;

            if (member.socialImgUrl && member.socialImgUrl.trim() !== "") {
                imgUrl = member.socialImgUrl;
            } else if (id) {
                const profile = await memberService.profile(id);
                imgUrl = profile.filePath || "https://image.ohousecdn.com/i/bucketplace-v2-development/uploads/default_images/avatar.png?w=144&h=144&c=c";
            } else {
                imgUrl = "https://image.ohousecdn.com/i/bucketplace-v2-development/uploads/default_images/avatar.png?w=144&h=144&c=c";
            }

            if (profileImg) {
                profileImg.src = imgUrl;
            }
        });


        if (profileNameEl) {
            profileNameEl.textContent = member.memberName || member.memberEmail || '사용자';
        }

        if (logoutLink) {
            logoutLink.addEventListener('click', async (e) => {
                e.preventDefault();
                try { await memberService.logout(); } catch (_) {}
                location.href = '/mobile/login';
            }, { once: true });
        }

    }).catch(() => {
        if (profileWrap) profileWrap.style.display = 'none';
        if (guestWrap)   guestWrap.style.display   = '';
        if (logoutLink)  logoutLink.style.display  = 'none';
    });
}

