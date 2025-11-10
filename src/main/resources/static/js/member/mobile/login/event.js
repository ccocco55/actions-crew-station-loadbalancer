memberService.resetCookies();

// 일반 회원, 게스트 회원 구분 버튼에 따라 폼 태그 바꿔주기
const memberDivision = document.querySelector("div.login-part-btn");

memberDivision.addEventListener("click", (e) => {
    e.target.classList.add("active");
    if (e.target.classList[0] === "normal") {
        document.querySelector("form.member-login").style.display = "block";
        document.querySelector("form.guest-login").style.display = "none";
        document.querySelector("button.guest").classList.remove("active");
        document.querySelector("button.normal").classList.add("active");
    } else {
        document.querySelector("form.member-login").style.display = "none";
        document.querySelector("form.guest-login").style.display = "block";
        document.querySelector("button.normal").classList.remove("active");
        document.querySelector("button.guest").classList.add("active");
    }
});

// 입력 창에 빈 값이면 에러 표시해주기

const inputTags = document.querySelectorAll("input");

inputTags.forEach((input) => {
    input.addEventListener("blur", (e) => {
        if (input.value === "") {
            input.classList.add("error");
        }
        else {
            input.classList.remove("error");
        }
    });
});

const button = document.querySelector('.login-member-btn');
const loginError = document.querySelector(".login-error");

button.addEventListener('click', async () => {
    const email = document.querySelector(".member-email").value;
    const password = document.querySelector(".member-password").value;
    try {
        const result = await memberService.login({memberEmail: email, memberPassword: password});
        if(result.accessToken){
            location.href = '/gifts';

        }
    } catch (err) {
        loginError.innerHTML = `<span>이메일 또는 비밀번호가 잘못 되었습니다.</span>`
        inputTags.forEach((input) => {
            input.classList.add("error");

        })
    }
})

const guestButton = document.querySelector(".login-guest-btn");

guestButton.addEventListener("click", async(e) => {
    loginError.innerHTML = ``;
    const guestID = document.querySelector(".guest-id").value;
    const guestPhone = document.querySelector(".guest-phone").value;
    try {
        const result = await memberService.guestLogin({guestOrderNumber: guestID, guestPhone: guestPhone});
        if(result.accessToken){
            location.href = '/guest/order-detail';

        }
    } catch (err) {
        loginError.innerHTML = `<span>핸드폰 번호 또는 주문번호가 잘못 되었습니다.</span>`
        inputTags.forEach((input) => {
            input.classList.add("error");

        })
    }
})


// social 로그인


// 카카오 로그인
const kakaoLoginButton = document.querySelector(".kakao");
kakaoLoginButton.addEventListener("click", (e) => {
    window.location.href = "/oauth2/authorization/kakao";
});

// 네이버 로그인
const naverLoginButton = document.querySelector(".naver");
naverLoginButton.addEventListener("click", (e) => {
    window.location.href = "/oauth2/authorization/naver";
});

// 구글 로그인
const googleLoginButton = document.querySelector(".google");
googleLoginButton.addEventListener("click", (e) => {
    window.location.href = "/oauth2/authorization/google";
});

