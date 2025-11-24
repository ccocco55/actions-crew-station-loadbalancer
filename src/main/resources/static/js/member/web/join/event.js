// 빈 값 유효성
const inputTags = document.querySelectorAll("input.form-control.essential");

inputTags.forEach((inputTag) => {
    inputTag.addEventListener("blur", (e) => {
        let error;
        if (inputTag.parentElement.parentElement.nextElementSibling) {
            error = inputTag.parentElement.parentElement.nextElementSibling;
        } else {
            error =
                inputTag.parentElement.parentElement.parentElement
                    .nextElementSibling;
        }

        if (inputTag.value.trim() === "") {
            inputTag.classList.add("error");
            error.style.display = "block";
            error.firstElementChild.textContent = "필수 입력 항목입니다.";
        } else {
            if (error.firstElementChild.textContent === "필수 입력 항목입니다.") {
                inputTag.classList.remove("error");
                error.style.display = "none";
            }
        }
    });
});

// 프로필 이미지
const input = document.querySelector(".img-input");
const profileImg = document.querySelector(".profile-img");

input.addEventListener("change", (e) => {
    const file = e.target.files[0]; // 업로드한 첫 번째 파일
    if (!file) return;

    if (!file.type.startsWith("image/")) {
        alert("이미지 파일만 업로드할 수 있습니다.");
        input.value = "";
        return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
        profileImg.src = event.target.result;
    };
    reader.readAsDataURL(file);
});

// 성별 선택
const genderRadioes = document.querySelectorAll(".gender-radio");

genderRadioes.forEach((radio) => {
    radio.addEventListener("change", (e) => {
        console.log("라디오 변화");

        document.querySelectorAll(".gender-label").forEach((label) => {
            label.classList.remove("active");
        });

        const parentLabel = e.target.closest(".gender-label");
        if (parentLabel) {
            parentLabel.classList.add("active");
        }

        error = document.querySelector("div.error-text-gender");
        error.style.display = "none";
    });
});



// 휴대전화 번호 검사

const memberPhone = document.querySelector("#memberPhone");
const phoneText = document.querySelector(".error-text-phone");
const phoneTextSpan = document.querySelector(".error-text-phone span");

memberPhone.addEventListener("keyup", (e) => {
    const phone = memberPhone.value.replace(/[^0-9]/g, "");
    memberPhone.value = phone; // 자동으로 숫자만 입력되게 정리

    const phoneRegex = /^010\d{8}$/;

    if (!phoneRegex.test(콜)) {
        phoneText.style.display = "block";
        phoneTextSpan.innerText = "번호를 다시 확인해 주세요.";

        memberPhone.classList.add("error");
    } else {
        phoneText.style.display = "none";
        phoneTextSpan.innerText = "";

        memberPhone.classList.remove("error");
    }
});



// 휴대전화 인증 체크 부분
const inputPhone = document.querySelector("input.phone");
const codeSendBtn = document.querySelector("button.phone-certification");
const codeCheckBtn = document.querySelector("button.code-check");
const code = document.querySelector("input.essential.code");
let codeSendCheck = true;
let time = 5 * 60;
let timer;
function updateTimer(timer) {
    const minutes = Math.floor(time / 60);
    const seconds = time % 60;
    document.querySelector(".limit-time").textContent = `${minutes}:${
        seconds < 10 ? "0" + seconds : seconds
    }`;

    if (time > 0) {
        time--;
    } else {
        mailSendCheck = true;
        clearInterval(timer); // 0초가 되면 멈춤
    }
}

const codeInputWrap = document.querySelector("div.phone-check");
inputPhone.addEventListener("input", (e) => {
    if (inputPhone.value.trim() === "") {
        codeSendBtn.disabled = true;
    } else {
        codeSendBtn.disabled = false;
    }
});

codeSendBtn.addEventListener("click", (e) => {
    if (!codeSendCheck) return;
    clearInterval(timer);
    time = 5 * 60;

    codeSendCheck = false;
    codeInputWrap.style.display = "block";
    timer = setInterval(updateTimer, 1000);
    updateTimer(timer);
});

let result = null;

codeSendBtn.addEventListener("click", async (e) => {
    const phone = inputPhone.value;
    result = await memberService.checkPhone(콜);

    console.log(result.code);
});

code.addEventListener("input", (e) => {
    if (code.value.trim() === "") {
        codeCheckBtn.disabled = true;
    } else {
        codeCheckBtn.disabled = false;
    }
});

codeCheckBtn.addEventListener("click", (e) => {
    //코드 체크 성공 시
    if (code.value === result.code) {
        inputPhone.readOnly = true;
        clearInterval(timer);
        codeInputWrap.style.display = "none";
        const errorTag = document.querySelector("div.error-text-phone");
        errorTag.style.display = "block";
        errorTag.firstElementChild.textContent = "";

        codeSendBtn.disabled = true;
    } else {
        codeSendCheck = true;
        code.classList.add("error");
        const errorTag = document.querySelector("div.error-text-phone");
        errorTag.style.display = "block";
        errorTag.firstElementChild.textContent = "인증번호가 다릅니다.";
    }
});


// 이메일 가능 검사
const emailInput = document.querySelector("input.email");
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const emailText = document.querySelector(".error-text-email");
const emailTextSpan = document.querySelector(".error-text-email span");

emailInput.addEventListener("keyup", async (e) => {
    const email = emailInput.value.trim();

    // 이메일 형식 체크
    if (!emailRegex.test(email)) {
        emailText.style.display = "block";
        emailTextSpan.innerText = "이메일 형식이 올바르지 않습니다.";
        return;
    }

    // 이메일 중복 체크
    let check = await memberService.checkEmail(email);

    if (check) {
        emailText.style.display = "block";
        emailTextSpan.innerText = "이미 사용 중인 이메일입니다.";
    } else {
        emailText.style.display = "none";
        emailTextSpan.innerText = "";
    }
});

// 비밀번호 확인 유효성

const passwordInput = document.querySelector(
    "input.form-control.essential.password"
);
const passwordCheckInput = document.querySelector(
    "input.form-control.essential.password-check"
);
const passwordError = document.querySelector("div.error-text-password");
const passwordCheckError = document.querySelector(
    "div.error-text-password-check"
);
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

passwordInput.addEventListener("blur", (e) => {
    if (passwordInput.value.trim() === "") {
        passwordError.style.display = "block";
        passwordError.firstElementChild.textContent = "필수 입력 항목입니다.";
    } else if (passwordInput.value.trim() !== passwordCheckInput.value.trim()) {
        passwordCheckError.style.display = "block";
        passwordCheckError.firstElementChild.textContent =
            "비밀번호가 다릅니다.";
    } else if (passwordInput.value.trim() === passwordCheckInput.value.trim()) {
        passwordCheckError.style.display = "none";
    } else {
        passwordError.style.display = "none";
    }
});

passwordInput.addEventListener("keyup", (e) => {
    const password = passwordInput.value.trim();

    if (!passwordRegex.test(password)) {
        passwordError.style.display = "block";
        passwordError.firstElementChild.textContent =
            "영문, 숫자를 포함한 8자 이상의 비밀번호를 입력해주세요.";

        passwordInput.classList.add("error");
    } else {
        passwordError.style.display = "none";
        passwordError.firstElementChild.textContent = "";

        passwordInput.classList.remove("error");
    }
});

passwordCheckInput.addEventListener("blur", (e) => {
    if (passwordCheckInput.value.trim() === "") {
        passwordCheckError.style.display = "block";
        passwordCheckError.firstElementChild.textContent =
            "필수 입력 항목입니다.";
    } else if (passwordInput.value.trim() !== passwordCheckInput.value.trim()) {
        passwordCheckError.style.display = "block";
        passwordCheckError.firstElementChild.textContent =
            "비밀번호가 다릅니다.";
        passwordInput.classList.add("error");
    } else if (passwordInput.value.trim() === passwordCheckInput.value.trim()) {
        passwordCheckError.style.display = "none";
        passwordCheckInput.classList.remove("error");
    }
});

// 생년월일 확인

const birthInput = document.querySelector(
    "input.birth"
);
const birthError = document.querySelector("div.error-text-birth");
const birthCheckError = document.querySelector(
    "div.error-text-birth span"
);
const birthRegex = /^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$/;


birthInput.addEventListener("keyup", (e) => {
    if (birthRegex.test(birthInput.value)) {
        birthError.style.display ="none";
        birthInput.classList.remove("error");
    } else {
        birthError.style.display ="block";
        birthCheckError.innerText = "생년월일을 확인해 주세요.";
        birthInput.classList.add("error");
    }
})

// 주소 찾기



const addressBtn =document.querySelector("#addressBtn");


addressBtn.addEventListener("click",(e)=>{
    getAddressWindow();
})

const getAddressWindow = () => {
    new daum.Postcode({
        oncomplete: function(data) {
            // 팝업에서 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

            // 도로명 주소의 노출 규칙에 따라 주소를 표시한다.
            // 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
            let roadAddr = data.roadAddress; // 도로명 주소 변수
            let addr = "";
            let extraRoadAddr = ''; // 참고 항목 변수

            // 법정동명이 있을 경우 추가한다. (법정리는 제외)
            // 법정동의 경우 마지막 문자가 "동/로/가"로 끝난다.
            if(data.bname !== '' && /[동|로|가]$/g.test(data.bname)){
                extraRoadAddr += data.bname;
            }
            // 건물명이 있고, 공동주택일 경우 추가한다.
            if(data.buildingName !== '' && data.apartment === 'Y'){
                extraRoadAddr += (extraRoadAddr !== '' ? ', ' + data.buildingName : data.buildingName);
            }
            // 표시할 참고항목이 있을 경우, 괄호까지 추가한 최종 문자열을 만든다.
            if(extraRoadAddr !== ''){
                extraRoadAddr = ' (' + extraRoadAddr + ')';
            }

            if (data.userSelectedType === 'R') { // 사용자가 도로명 주소를 선택했을 경우
                addr = data.roadAddress;
            } else { // 사용자가 지번 주소를 선택했을 경우(J)
                addr = data.jibunAddress;
            }

            // 우편번호와 주소 정보를 해당 필드에 넣는다.
            document.querySelector(".memberZipCode").value = data.zonecode;
            document.querySelector(".memberAddress").value = addr;

            // 참고항목 문자열이 있을 경우 해당 필드에 넣는다.
            if(roadAddr !== ''){
                document.querySelector(".memberAddressDetail").value = extraRoadAddr;
            } else {
                document.querySelector(".memberAddressDetail").value = '';
            }
        }
    }).open();
}

// MBTI 유효성 검사
const mbtiInput = document.querySelector("input.mbti");
const mbtiError = document.querySelector(".error-text-mbti");
const mbtiErrorSpan = document.querySelector(".error-text-mbti span");
const mbtiRegex = /^(?:[EI][SN][TF][JP])$/i;

mbtiInput.addEventListener("keyup", () => {
    const value = mbtiInput.value.trim().toUpperCase(); // 대문자로 변환
    if (mbtiInput.value) {
        if (!mbtiRegex.test(value)) {
            mbtiError.style.display = "block";
            mbtiErrorSpan.textContent = "올바른 MBTI 유형을 입력해주세요.";
            mbtiInput.classList.add("error");
        } else {
            mbtiError.style.display = "none";
            mbtiErrorSpan.textContent = "";
            mbtiInput.classList.remove("error");
            mbtiInput.value = value; // 대문자로 유지
        }
    } else {
        mbtiError.style.display = "none";
        mbtiErrorSpan.textContent = "";
        mbtiInput.classList.remove("error");
    }
});


// 유효성 검사 다 체크

const nameInput = document.querySelector(".form-control.essential.name");
const errorTextName = document.querySelector((".error-text-name"));

function validateForm() {
    // 이름 검사 (이름이 없거나 에러 메시지가 보이면 false)
    if (nameInput.value.trim() === "" || errorTextName.style.display === "block") {
        return false;
    }

    // 성별 선택 검사
    const genderChecked = document.querySelectorAll(".gender-radio:checked").length > 0;
    if (!genderChecked) return false;

    // 이메일 형식/중복 검사
    if (document.querySelector(".error-text-email").style.display === "block") {
        return false;
    }

    // 비밀번호 검사
    if (
        document.querySelector(".error-text-password").style.display === "block" ||
        document.querySelector(".error-text-password-check").style.display === "block"
    ) {
        return false;
    }

    // 생년월일 검사
    if (document.querySelector(".error-text-birth").style.display === "block") {
        return false;
    }

    // 주소(우편번호 + 기본 주소) 검사
    const zip = document.querySelector(".memberZipCode").value.trim();
    const addr = document.querySelector(".memberAddress").value.trim();
    if (zip === "" || addr === "") {
        return false;
    }

    // MBTI 검사
    if (mbtiError.style.display === "block") {
        return false;
    }

    // 휴대폰 인증 확인 (readOnly 아니면 아직 미완료)
    if (!inputPhone.readOnly) {
        return false;
    }

    // 모든 조건을 통과하면 true
    return true;
}

// 회원가입

const submitBtn = document.querySelector(".submit-btn");

submitBtn.disabled = true;

document.addEventListener("click", () => {
    submitBtn.disabled = !validateForm();
    console.log(validateForm());
});
