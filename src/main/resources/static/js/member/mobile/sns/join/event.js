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

    if (!phoneRegex.test(phone)) {
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
    result = await memberService.checkPhone(phone);

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


// 생년월일 확인

const birthInput = document.querySelector("input.birth");
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
// 우편번호 찾기 찾기 화면을 넣을 element
var element_wrap = document.getElementById('wrap');

function foldDaumPostcode() {
    // iframe을 넣은 element를 안보이게 한다.
    element_wrap.style.display = 'none';
}

function sample3_execDaumPostcode() {
    // 현재 scroll 위치를 저장해놓는다.
    var currentScroll = Math.max(document.body.scrollTop, document.documentElement.scrollTop);
    new daum.Postcode({
        oncomplete: function(data) {
            // 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

            // 각 주소의 노출 규칙에 따라 주소를 조합한다.
            // 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
            var addr = ''; // 주소 변수
            var extraAddr = ''; // 참고항목 변수

            //사용자가 선택한 주소 타입에 따라 해당 주소 값을 가져온다.
            if (data.userSelectedType === 'R') { // 사용자가 도로명 주소를 선택했을 경우
                addr = data.roadAddress;
            } else { // 사용자가 지번 주소를 선택했을 경우(J)
                addr = data.jibunAddress;
            }

            // 사용자가 선택한 주소가 도로명 타입일때 참고항목을 조합한다.
            if(data.userSelectedType === 'R'){
                // 법정동명이 있을 경우 추가한다. (법정리는 제외)
                // 법정동의 경우 마지막 문자가 "동/로/가"로 끝난다.
                if(data.bname !== '' && /[동|로|가]$/g.test(data.bname)){
                    extraAddr += data.bname;
                }
                // 건물명이 있고, 공동주택일 경우 추가한다.
                if(data.buildingName !== '' && data.apartment === 'Y'){
                    extraAddr += (extraAddr !== '' ? ', ' + data.buildingName : data.buildingName);
                }
                // 표시할 참고항목이 있을 경우, 괄호까지 추가한 최종 문자열을 만든다.
                if(extraAddr !== ''){
                    extraAddr = ' (' + extraAddr + ')';
                }
                // 조합된 참고항목을 해당 필드에 넣는다.
                document.getElementById("sample3_extraAddress").value = extraAddr;

            } else {
                document.getElementById("sample3_extraAddress").value = '';
            }

            // 우편번호와 주소 정보를 해당 필드에 넣는다.
            document.getElementById('sample3_postcode').value = data.zonecode;
            document.getElementById("sample3_address").value = addr;
            // 커서를 상세주소 필드로 이동한다.
            document.getElementById("sample3_extraAddress").focus();

            // iframe을 넣은 element를 안보이게 한다.
            // (autoClose:false 기능을 이용한다면, 아래 코드를 제거해야 화면에서 사라지지 않는다.)
            element_wrap.style.display = 'none';

            // 우편번호 찾기 화면이 보이기 이전으로 scroll 위치를 되돌린다.
            document.body.scrollTop = currentScroll;
        },
        // 우편번호 찾기 화면 크기가 조정되었을때 실행할 코드를 작성하는 부분. iframe을 넣은 element의 높이값을 조정한다.
        onresize : function(size) {
            element_wrap.style.height = '500px';
        },
        width : '100%',
        height : '100%'
    }).embed(element_wrap);

    // iframe을 넣은 element를 보이게 한다.
    element_wrap.style.display = 'block';
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

    return true;
}

// 회원가입

const submitBtn = document.querySelector(".submit-btn");

submitBtn.disabled = true;

document.addEventListener("click", () => {
    submitBtn.disabled = !validateForm();
    console.log(submitBtn.disabled)
});
