document.addEventListener("DOMContentLoaded", () => {
    initModifyEvents();
    initDeleteModalEvents();
});

 // 회원 정보 수정 관련 이벤트
function initModifyEvents() {
    const fileInput = document.querySelector("#profile");
    const profileImg = document.querySelector(".modify-label img");
    const addressBtn = document.querySelector("#addressBtn");
    const submitBtn = document.querySelector(".submit");
    const form = document.querySelector(".modify-form");

    // 프로필 이미지 미리보기
    if (fileInput && profileImg) {
        fileInput.addEventListener("change", (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    profileImg.src = event.target.result;
                };
                reader.readAsDataURL(file);
            }
        });
    }

    // 주소 변경 버튼 클릭 → 다음 주소검색창 열기
    if (addressBtn) {
        addressBtn.addEventListener("click", () => {
            new daum.Postcode({
                oncomplete: function (data) {
                    let roadAddr = data.roadAddress;
                    let addr = "";
                    let extraRoadAddr = "";

                    // 법정동/건물명 등 참고항목 구성
                    if (data.bname !== '' && /[동|로|가]$/g.test(data.bname)) {
                        extraRoadAddr += data.bname;
                    }
                    if (data.buildingName !== '' && data.apartment === 'Y') {
                        extraRoadAddr += (extraRoadAddr !== '' ? ', ' + data.buildingName : data.buildingName);
                    }
                    if (extraRoadAddr !== '') {
                        extraRoadAddr = '(' + extraRoadAddr + ')';
                    }

                    // 도로명 / 지번 주소 구분
                    addr = data.userSelectedType === 'R' ? data.roadAddress : data.jibunAddress;

                    document.querySelector("#zipCode").value = data.zonecode;
                    document.querySelector("#addressInput").value = addr;
                    document.querySelector("#detailAddress").value = extraRoadAddr || "";
                }
            }).open();
        });
    }

    // 완료 버튼 클릭 시 폼 제출
    if (submitBtn && form) {
        submitBtn.addEventListener("click", (e) => {
            e.preventDefault();

            if (confirm("회원 정보를 수정하시겠습니까?")) {
                form.submit();
            }
        });
    }
}

 // 회원 탈퇴 모달 이벤트
function initDeleteModalEvents() {
    const deleteBtn = document.getElementById("deleteBtn");
    const modal = document.getElementById("deleteModal");
    const cancelBtn = modal ? modal.querySelector(".cancel") : null;

    if (deleteBtn && modal) {
        deleteBtn.addEventListener("click", () => {
            modal.style.display = "flex";
        });
    }

    if (cancelBtn) {
        cancelBtn.addEventListener("click", () => {
            modal.style.display = "none";
        });
    }

    // 모달 바깥 클릭 시 닫기
    if (modal) {
        modal.addEventListener("click", (e) => {
            if (e.target === modal) {
                modal.style.display = "none";
            }
        });
    }
}
