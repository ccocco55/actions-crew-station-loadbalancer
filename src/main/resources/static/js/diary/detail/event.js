// 일기 공개/비공개 설정

const secretCheckbox = document.querySelector(".secret-checkbox");
const secretToggle = document.querySelector(".secret-toggle");
const lockIcon = document.querySelector(".lock");
const unlockIcon = document.querySelector(".unlock");

secretToggle?.addEventListener("click", async (e) => {
    secretCheckbox.checked = secretToggle.classList.toggle("active");
    console.log(secretCheckbox.checked)
    console.log(document.getElementById("postId").dataset.post);
    const {message,status}= await diaryDetailService.changeSecret({"check":secretCheckbox.checked,"diaryId":+document.getElementById("postId").dataset.post});
    toastModal(message);
    if(status ===404){
        location.href="/diaries";
    }
    if (secretCheckbox.checked) {
        lockIcon.classList.remove("hidden");
        unlockIcon.classList.add("hidden");
    } else {
        lockIcon.classList.add("hidden");
        unlockIcon.classList.remove("hidden");
    }

});

// 이미지 팝업

const targets = document.querySelectorAll(".target");
const images = document.querySelectorAll(".diary-img");
const modal = document.querySelector(".img-modal");
const modalImg = document.querySelector(".img-modal img");
const closeBtn = document.querySelector(".img-close-button");

targets.forEach((target, i) => {
    let targetId = target.id.split("_")[1];
    if(document.getElementById(`image_${targetId}`)){
        console.log(i)
        const imgSrc = document.getElementById(`image_${targetId}`).getAttribute("src");
        target.addEventListener("click", () => {
            console.log("클릭이벤트")
            modalImg.setAttribute("src", imgSrc);
            modal.style.display = "flex";
        });
    }else{
        target.style.cursor = "unset";
    }

});

// 닫기 버튼
closeBtn.addEventListener("click", () => {
    modal.style.display = "none";
});

// 모달 바깥 클릭하면 닫기
modal.addEventListener("click", (e) => {
    if (e.target === modal) {
        modal.style.display = "none";
    }
});

// 신고하기 버튼

const reportBtn = document.querySelector(".report-button");
const reportModal = document.querySelector(".report-modal");
const replyReporyBtn = document.querySelector(".reply-report-button");

reportBtn.addEventListener("click", (e) => {
    console.log("asdasds")
    isReply = false;
    reportModal.classList.add("active");
});

// 신고하기 창 끄기

const reportCloseBtn = document.querySelector(".close-button");

reportCloseBtn.addEventListener("click", (e) => {
    reportModal.classList.remove("active");
    selectFirstReportRadio();
});

// 신고하기 창 신고 종류 고르기

const reportOptions = document.querySelectorAll(".report-content");
const radioBtns = document.querySelectorAll(".radio-button");

reportOptions.forEach((reportOption) => {
    reportOption.addEventListener("click", (e) => {
        radioBtns.forEach((radioBtn) => {
            radioBtn.classList.remove("active");
            const btn = radioBtn.querySelector(".radio");
            btn.checked = false;
        });

        const btn = reportOption.querySelector(".radio");

        btn.checked = true;
        const radioButton = reportOption.querySelector(".radio-button");
        radioButton.classList.add("active");
    });
});

// 신고하기 창 제출 버튼


submitReportBtn.addEventListener("click", (e) => {
    // reportModal.classList.remove("active");
    confirmReportModal.style.display = "flex";

});

// 신고하기 창 제출/끄기 후 첫번째 라디오 버튼 선택

console.log(document.querySelector("input[name='reason']:checked").value);
confirmReportYes.addEventListener("click", async (e) => {

    const reportContent = document.querySelector("input[name='reason']:checked").value;
    console.log(reportContent);
    const postId = document.getElementById("postId").dataset.post;
    // const memberId = document.getElementById("memberId").value;
    if(!isReply){

        const {message, status} = await diaryDetailService.report({
            reportContent: reportContent,
            postId: postId
        })
        console.log(message)
        console.log(status)

        toastModal(message);
        if (status === 404) {
            location.href = "/diaries"
        }
    }else{
        const{message,status} = await  replyService.report({postId:postId,reportContent:reportContent,replyId:confirmReportYes.dataset.id})
        toastModal(message);
        if (status === 404) {
            location.href = "/diaries"
        }
    }
    confirmReportModal.style.display = "none";
    document.getElementById("reportModal").classList.remove("active");
});

confirmReportNo.addEventListener("click", () => {
    confirmReportModal.style.display = "none";
});


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
    }, 3000);
}

// 댓글 입력 버튼 활성화/비활성화

const input = document.querySelector(".input");
const enterButton = document.querySelector(".enter-button");

input.addEventListener("input", (e) => {
    if (e.target.value.length > 0 && e.target.value.trim()!=="") {
        enterButton.classList.add("active");
        enterButton.disabled = false;
    } else {
        enterButton.classList.remove("active");
        enterButton.disabled = true;
    }
});

// 댓글 입력 버튼 클릭 시 입력 비활성화

enterButton.addEventListener("click", (e) => {
    input.value = "";
    enterButton.classList.remove("active");
    enterButton.disabled = true;
});

// 댓글 수정

document
    .querySelectorAll(".modify-reply-button")
    .forEach((modifyReplyButton) => {
        modifyReplyButton.addEventListener("click", () => {
            const replyContent = modifyReplyButton.closest(".reply-content");
            const replyFlexBox = replyContent.querySelector(
                "div[style='display: flex;']"
            );
            const replyTextDiv = replyFlexBox.querySelector(
                ".reply-content-text"
            );
            const originalText = replyTextDiv.textContent;

            const input = document.createElement("input");

            input.type = "text";
            input.className = "reply-edit-input";
            input.value = originalText;

            // 저장 버튼 만들기
            const saveButton = document.createElement("button");
            saveButton.textContent = "저장";
            saveButton.className = "save-reply-button";

            // 기존 텍스트 제거하고 input, 버튼 만들기
            replyFlexBox.innerHTML = "";
            replyFlexBox.appendChild(input);
            replyFlexBox.appendChild(saveButton);

            // 다시 텍스트로
            saveButton.addEventListener("click", () => {
                const newText = input.value;

                // 새로운 텍스트 div 생성
                const newTextDiv = document.createElement("div");
                newTextDiv.className = "reply-content-text";
                newTextDiv.textContent = newText;

                // input과 버튼 제거하고 텍스트 복원
                replyFlexBox.innerHTML = "";
                replyFlexBox.appendChild(newTextDiv);
            });
        });
    });

const removeContentModal = document.querySelector(".remove-modal-content");
const removeContentNoButton = document.querySelector(".remove-no-content");
console.log(removeContentNoButton);
const removeContentOkButton = document.querySelector(".remove-ok-content");
const removeContentBtn = document.querySelector(".remove-button.remove-content-button");
removeContentBtn?.addEventListener("click",(e)=>{
    removeContentModal.style.display = "block";
})
removeContentNoButton.addEventListener("click",(e)=>{
    console.log("123")
    removeContentModal.style.display = "none";
})
removeContentOkButton.addEventListener("click",(e)=>{
    const postId = +document.getElementById("postId").dataset.post;
    location.href=`/diaries/delete/${postId}`;

})
// 페이지 클릭

const numberButtons = document.querySelectorAll(".number-button");

numberButtons.forEach((numberButton) => {
    numberButton.addEventListener("click", (e) => {
        numberButtons.forEach((btn) => btn.classList.remove("active"));
        numberButton.classList.add("active");
    });
});

// 게시물 좋아요 버튼

const likeButton = document.querySelector(".sticky-like-button");
// const toast = document.querySelector("div.toast");
const toastText = document.querySelector("p.toast-text");
let likeClickable = true; // 광클 방지용 플래그
likeButton.addEventListener("click", async (e) => {
    if(!likeClickable) return;
    likeClickable = false;
    const likeIcon = likeButton.querySelector(".like-before");
    const span = document.querySelector(".like-total");

    const {message,status} = await diaryDetailService.like({postId: Number(likeButton.dataset.post)}, likeIcon.classList.contains("active"))
    toast.style.display = "block";
    toastText.textContent = message;
    toast.classList.remove("hide");
    toast.classList.add("show");

    if(status === 200){
        const likeCount = Number(span.textContent);
        if (likeIcon.classList.contains("active")) {
            span.textContent = likeCount -1;
        } else {
            span.textContent = likeCount + 1;
        }
        likeIcon.classList.toggle("active");
    }
    // 토스트 애니메이션 처리
    setTimeout(() => {
        toast.classList.remove("show");
        toast.classList.add("hide");

        setTimeout(() => {
            toast.style.display = "none";
            if(status === 404){
                console.log(message)
                location.reload();
            }
            likeClickable = true;
        }, 1000);
    }, 2000);

});

// 댓글로가기 버튼

const goToCommentButton = document.querySelector(".go-reply");

goToCommentButton.addEventListener("click", (e) => {
    const commentSection = document.querySelector(".reply-container");
    commentSection.scrollIntoView({ behavior: "smooth" });
});

// 공유하기 버튼 클릭 이벤트

const shareButton = document.querySelector(".sticky-share-button");
const toast = document.querySelector(".toast");

shareButton.addEventListener("click", (e) => {
    if(!likeClickable) return
    toast.style.display = "block";
    toast.classList.remove("hide");
    toast.classList.add("show");
    toastText.textContent ="클립보드에 복사되었습니다."
    setTimeout(() => {
        toast.classList.remove("show");
        toast.classList.add("hide");
        setTimeout(() => {
            toast.style.display = "none";
        }, 500);
    }, 3000);
    clip();
});

function clip() {
    var url = "";
    var textarea = document.createElement("textarea");
    document.body.appendChild(textarea);
    url = window.location.href; // 현재 URL을 가져옵니다.
    textarea.value = url;
    textarea.select(); // 텍스트 영역의 내용을 선택합니다.
    document.execCommand("copy"); // 선택된 내용을 클립보드에 복사합니다.
    document.body.removeChild(textarea); // 텍스트 영역을 제거합니다.
}


