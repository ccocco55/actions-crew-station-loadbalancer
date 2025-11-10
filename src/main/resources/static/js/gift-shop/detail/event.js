// 모달 관련 (공통)
function setupModal(modalId, openSelector, closeSelector, onClose) {

    console.log(openSelector);
    console.log("선택햇습니다.")
    const modal = document.getElementById(modalId);
    const openBtns = document.querySelectorAll(openSelector);
    const closeBtn = modal ? modal.querySelector(closeSelector) : null;

    if (!modal || openBtns.length === 0 || !closeBtn) {
        console.warn("모달 요소를 찾을 수 없음:", modalId, openSelector, closeSelector);
        return;
    }

    // 열기 버튼들
    openBtns.forEach((btn) => {
        btn.addEventListener("click", async (e) => {
            console.log(modalId);
            if (modalId === "myModal") {
                const postId = document.getElementById("postId").dataset.post;
                console.log(123)
                const {isGuest, message, status,count} = await purchaseDetailService.requestToSell({
                    purchaseId: postId
                })
                console.log(isGuest)

                if (!isGuest) {
                    if(status === 200){
                        document.querySelector("span.product-stock").textContent = `${count}개 남음`;
                    }
                    toastModal(message);
                } else {
                    e.stopPropagation();
                    modal.classList.add("active");
                }
            } else if (modalId === "reportModal") {
                modal.classList.add("active");
            }
        });
    });

    // 닫기 버튼
    closeBtn.addEventListener("click", () => {
        modal.classList.remove("active");
        if (onClose) onClose();
    });

    // 바깥 클릭 시 닫기
    modal.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.classList.remove("active");
            if (onClose) onClose();
        }
    });
}
document.addEventListener("DOMContentLoaded", () => {
    // 슬라이드 관련
    const carouselList = document.querySelector(".carousel-list");
    const slides = document.querySelectorAll(".carousel-list-entry");
    const dots = document.querySelectorAll(".carousel-paginator-page");
    const thumbnails = document.querySelectorAll(".product-cover-image-list .image");



    setupModal("myModal", "#openBuyingModalBtn", ".close");
    setupModal("reportModal", ".gift-shop-post-report-btn", ".close-button", () => selectFirstReportRadio());

    // 신고하기 라디오 선택
    const reportOptions = document.querySelectorAll(".report-content");
    const radioBtns = document.querySelectorAll(".radio-button");

    if (reportOptions.length > 0 && radioBtns.length > 0) {
        reportOptions.forEach((reportOption) => {
            reportOption.addEventListener("click", () => {
                // 기존 선택 해제
                radioBtns.forEach((radioBtn) => {
                    radioBtn.classList.remove("active");
                    const btn = radioBtn.querySelector(".radio");
                    if (btn) btn.checked = false;
                });

                // 새 선택 적용
                const btn = reportOption.querySelector(".radio");
                if (btn) btn.checked = true;
                const radioButton = reportOption.querySelector(".radio-button");
                if (radioButton) radioButton.classList.add("active");
            });
        });
    }

    // 신고하기 제출
    // const submitReportBtn = document.querySelector(".report-button-send");
    // const reportModal = document.getElementById("reportModal");
    // if (submitReportBtn && reportModal) {
    //     submitReportBtn.addEventListener("click", () => {
    //         reportModal.classList.remove("active");
    //         selectFirstReportRadio();
    //         alert("신고가 접수되었습니다.");
    //     });
    // }

    // 신고하기 첫번째 라디오 버튼 기본 선택
    function selectFirstReportRadio() {
        radioBtns.forEach((radioBtn, idx) => {
            const btn = radioBtn.querySelector(".radio");
            if (!btn) return;
            if (idx === 0) {
                radioBtn.classList.add("active");
                btn.checked = true;
            } else {
                radioBtn.classList.remove("active");
                btn.checked = false;
            }
        });
    }

    // 확인 모달 제어
    const form = document.getElementById("requestForm");
    const confirmModal = document.getElementById("confirmModal");
    const confirmYes = document.getElementById("confirmYes");
    const confirmNo = document.getElementById("confirmNo");

    if (form && confirmModal) {
        form.addEventListener("submit", (e) => {
            e.preventDefault();

            const addressInput = document.getElementById("addressInput");
            const detailAddress = document.getElementById("detailAddress");
            const phone = document.getElementById("phone");
            const zipCode = document.getElementById("zipCode");

            // 배송지 입력 체크
            if (!addressInput.value || addressInput.value.trim() === "") {
                alert("배송지를 입력해주세요.");
                addressInput.focus();
                return;
            }

            // 상세주소 입력 체크
            if (!detailAddress.value || detailAddress.value.trim() === "") {
                alert("상세주소를 입력해주세요.");
                detailAddress.focus();
                return;
            }

            // 우편번호 입력 체크
            if (!zipCode.value || zipCode.value.trim() === "") {
                alert("우편번호를 입력해주세요.");
                zipCode.focus();
                return;
            }

            // 핸드폰 번호 입력 체크
            if (!phone.value || phone.value.trim() === "") {
                alert("핸드폰 번호를 입력해주세요.");
                phone.focus();
                return;
            }

            // 핸드폰 번호 형식 체크 (숫자 10~11자리)
            const phonePattern = /^[0-9]{10,11}$/;
            if (!phonePattern.test(phone.value.trim())) {
                alert("핸드폰 번호 형식이 올바르지 않습니다. (숫자만 입력)");
                phone.focus();
                return;
            }

            confirmModal.style.display = "flex";
        });

        // 숫자만 입력되게 제약 추가
        const phoneInput = document.getElementById("phone");
        const zipCodeInput = document.getElementById("zipCode");

        if (phoneInput) {
            phoneInput.addEventListener("input", function () {
                this.value = this.value.replace(/[^0-9]/g, "");
            });
        }

        if (zipCodeInput) {
            zipCodeInput.addEventListener("input", function () {
                this.value = this.value.replace(/[^0-9]/g, "");
            });
        }

        if (confirmYes) {
            confirmYes.addEventListener("click", async () => {
                const form = document.getElementById("requestForm");
                const formData = new FormData(form);
                const {message, status,count} = await purchaseDetailService.requestToSell({
                    guest: true,
                    purchaseId: document.getElementById("postId").dataset.post,
                    memberPhone: formData.get("phone"),
                    address: formData.get("addressInput"),
                    addressZipCode: formData.get("zipCode"),
                    addressDetail: formData.get("addressDetail")
                })
                console.log("message + ::::::", message)
                confirmModal.style.display = "none";
                document.getElementById("myModal").style.display = "none";
                if (status === 200) {
                    document.querySelector("span.product-stock").textContent = `${count}개 남음`;
                    alert("요청이 전송되었습니다. 임시 주문번호는 입력하신 휴대폰 번호로 발송됩니다.");

                } else {
                    toastModal(message);

                }

            });
        }

        if (confirmNo) {
            confirmNo.addEventListener("click", () => {
                confirmModal.style.display = "none";
            });
        }

        confirmModal.addEventListener("click", (e) => {
            if (e.target === confirmModal) confirmModal.style.display = "none";
        });
    }

    const confirmReportModal = document.getElementById("confirmReportModal");
    const confirmReportYes = document.getElementById("confirmReportYes");
    const confirmReportNo = document.getElementById("confirmReportNo");
    const reportBtn = document.getElementById("reportBtn");
    reportBtn.addEventListener("click", (e) => {
        console.log(123)
        confirmReportModal.style.display = "flex";
    })

    confirmReportYes.addEventListener("click", async (e) => {
        const reportContent = document.querySelector("input[name='reason']:checked").value;
        console.log(reportContent);
        const postId = document.getElementById("postId").dataset.post;
        const {message, status} = await purchaseDetailService.report({
            reportContent: reportContent,
            postId: postId
        })
        console.log(message)
        console.log(status)
        confirmReportModal.style.display = "none";
        document.getElementById("reportModal").style.display = "none";

        if (status === 404) {
            location.href = "/gifts"
        }else{
            toastModal(message);
        }
    });

    confirmReportNo.addEventListener("click", () => {
        confirmReportModal.style.display = "none";
    });

    // 툴팁 관련
    const chemInfoBtn = document.querySelector(".openChemistryInfo");
    const chemTooltip = document.querySelector(".chemistryTooltip");

    if (chemInfoBtn && chemTooltip) {
        chemInfoBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            chemTooltip.style.display =
                chemTooltip.style.display === "block" ? "none" : "block";
        });

        document.addEventListener("click", (e) => {
            if (!chemTooltip.contains(e.target) && e.target !== chemInfoBtn) {
                chemTooltip.style.display = "none";
            }
        });
    }

    // 주소 검색 버튼 클릭 이벤트
    // const addressWrap = document.querySelector("#addressWrap");

    const modal = document.querySelector("#modal");
    const openBtn = document.querySelector("#openBtn");
    const closeBtn = document.querySelector("#closeBtn");
    const addressWrap = document.querySelector("#addressWrap");
    document.querySelector("#addressInput").addEventListener("click", (e) => {
        modal.classList.remove("hidden");
        console.log(123)
        getAddressWindow();
    });

    const getAddressWindow = () => {
        new daum.Postcode({
            oncomplete: function (data) {
                modal.classList.add("hidden");
                // 팝업에서 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

                // 도로명 주소의 노출 규칙에 따라 주소를 표시한다.
                // 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
                let roadAddr = data.roadAddress; // 도로명 주소 변수
                let addr = "";
                let extraRoadAddr = ''; // 참고 항목 변수

                // 법정동명이 있을 경우 추가한다. (법정리는 제외)
                // 법정동의 경우 마지막 문자가 "동/로/가"로 끝난다.
                if (data.bname !== '' && /[동|로|가]$/g.test(data.bname)) {
                    extraRoadAddr += data.bname;
                }
                // 건물명이 있고, 공동주택일 경우 추가한다.
                if (data.buildingName !== '' && data.apartment === 'Y') {
                    extraRoadAddr += (extraRoadAddr !== '' ? ', ' + data.buildingName : data.buildingName);
                }
                // 표시할 참고항목이 있을 경우, 괄호까지 추가한 최종 문자열을 만든다.
                if (extraRoadAddr !== '') {
                    extraRoadAddr = '(' + extraRoadAddr + ')';
                }

                if (data.userSelectedType === 'R') { // 사용자가 도로명 주소를 선택했을 경우
                    addr = data.roadAddress;
                } else { // 사용자가 지번 주소를 선택했을 경우(J)
                    addr = data.jibunAddress;
                }

                // 우편번호와 주소 정보를 해당 필드에 넣는다.
                document.querySelector("#zipCode").value = data.zonecode;
                document.querySelector("#addressInput").value = addr;

                // 참고항목 문자열이 있을 경우 해당 필드에 넣는다.
                if (roadAddr !== '') {
                    document.querySelector("#detailAddress").value = extraRoadAddr;
                } else {
                    document.querySelector("#detailAddress").value = '';
                }
            },
            width: '100%',
            height: '100%'   // 부모 div 크기에 맞춤
        }).embed(addressWrap);
    }
    closeBtn.addEventListener("click", () => {
        console.log(123);
        modal.classList.add("hidden");
    });
    // 슬라이드 로직
    let count = 1;
    const total = slides.length;
    let autoSlideInterval;


    function goTo(index) {
        count = index;
        // if (count < 0) count = total - 2;
        // if (count >= total) count = 2;
        console.log(count);
        carouselList.style.transform = `translateX(-${count * 100}%)`;
        carouselList.style.transition = `transform 0.5s`;
        if (count === total - 1) {
            setTimeout(() => {
                carouselList.style.transform = `translate(-100%)`;
                carouselList.style.transition = `transform 0s`;
            }, 500);
            count = 1;
        }

        dots.forEach((dot) => dot.classList.remove("selected"));
        if (dots[count - 1]) dots[count - 1].classList.add("selected");
    }

    function autoSlide() {
        goTo(count + 1);
    }

    function startAutoSlide() {
        autoSlideInterval = setInterval(autoSlide, 3000);
    }

    function stopAutoSlide() {
        clearInterval(autoSlideInterval);
    }

    function resetAutoSlide() {
        stopAutoSlide();
        startAutoSlide();
    }

    dots.forEach((dot, i) => {
        dot.addEventListener("click", () => {
            goTo(i + 1);
            resetAutoSlide();
        });
    });

    thumbnails.forEach((thumb, i) => {
        thumb.addEventListener("click", () => {

            if (thumbnails.length === 1) return;
            goTo(i + 1);
            resetAutoSlide();
            console.log(i + 1);

        });
    });
    if (total !== 1) {
        goTo(1);
        startAutoSlide();
    } else {
        carouselList.style.transform = `translateX(0)`;
    }
});

// 스크롤 탑 버튼
const scrollTopBtn = document.getElementById("scrollTopBtn");

scrollTopBtn.addEventListener("click", () => {
    window.scrollTo({top: 0, behavior: "smooth"});
});

window.addEventListener("scroll", () => {
    if (window.scrollY > 200) {
        scrollTopBtn.classList.add("show");
    } else {
        scrollTopBtn.classList.remove("show");
    }
});

// 마감 시각 표시
function startCountdown() {
    console.log(123)
    const timer = document.querySelector(
        ".product-limit-timer-time"
    );
    console.log(timer)
    const endTime = new Date(timer.dataset.endtime);
    console.log(endTime)

    function updateTimer() {
        const now = new Date();
        const diff = endTime - now;
        if (diff <= 0) {
            timer.textContent = "마감";
            return;
        }

        const totalSeconds = Math.floor(diff / 1000);

        const days = Math.floor(totalSeconds / (3600 * 24));
        const hours = String(Math.floor((totalSeconds % (3600 * 24)) / 3600)).padStart(2, "0");
        const minutes = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, "0");
        const seconds = String(totalSeconds % 60).padStart(2, "0");

        if (days > 0) {
            timer.textContent = `${days}일 ${hours}:${minutes}:${seconds} 남음`;
        } else {
            timer.textContent = `${hours}:${minutes}:${seconds} 남음`;
        }
    }

    updateTimer();
    timer.dataset.timeout = String(setInterval(updateTimer, 1000));
}

// 공유하기 버튼 클릭 이벤트
const shareButton = document.querySelector(".product-detail-header-share-btn-wrapper");
const toast = document.querySelector(".toast");
const toastText = document.querySelector("p.toast-text");

function toastModal(text) {
    toast.style.display = "block";
    toast.classList.remove("hide");
    toastText.textContent = text;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
        toast.classList.add("hide");
        setTimeout(() => {
            toast.style.display = "none";
        }, 500);
    }, 2000);
}

shareButton.addEventListener("click", (e) => {
    toastModal("클립보드에 복사되었습니다.");
    clip();
});

function clip() {
    var url = "";
    var textarea = document.createElement("textarea");
    document.body.appendChild(textarea);
    url = window.location.href; // 현재 URL
    textarea.value = url;
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
}


document.addEventListener("DOMContentLoaded", startCountdown);


document.querySelector("div.product-detail-container").addEventListener("click", (e) => {
    console.log(e.target)
    console.log(e.target.closest("div.modify-wrap"))
    if (e.target.closest("div.modify-wrap")) {
        console.log(123)
        console.log(e.target.closest("div.modify-wrap").querySelector("div.modify-container"));
        e.target.closest("div.modify-wrap").querySelector("div.modify-container").style.display = "flex";
        return
    }
    if(document.querySelector("div.modify-container")){
        document.querySelector("div.modify-container").style.display = "none";
    }
    if(e.target.closest("button.gift-shop-post-report-btn")){
        setupModal("reportModal", ".gift-shop-post-report-btn", ".close-button", () => selectFirstReportRadio());
    }

})

document.querySelector("div.del-post")?.addEventListener("click", (e) => {
    document.getElementById("delconfirmModal").classList.add("active");
})

document.getElementById("cancelDel").addEventListener("click", (e) => {
    document.getElementById("delconfirmModal").classList.remove("active");
})