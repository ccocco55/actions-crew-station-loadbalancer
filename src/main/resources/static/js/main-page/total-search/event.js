document.addEventListener("DOMContentLoaded", () => {
    if (typeof startCountdown === "function") {
        startCountdown();
    } else {
        console.warn("⚠️ startCountdown() not found!");
    }
});


// 여행 경로에서 경계선 주기
const color = [
    "#FF1744", // neon red (형광 빨강)
    "#FF9100", // neon orange (형광 주황)
    "#FFEA00", // neon yellow (형광 노랑)
    "#00E676", // neon green (형광 초록)
    "#2979FF", // neon blue (형광 파랑)
    "#304FFE", // neon navy (형광 남색 느낌)
    "#D500F9", // neon purple (형광 보라)
];
const tripPath = document.querySelectorAll(".trip-path");

tripPath.forEach((path) => {
    const markers = path.querySelectorAll(".marker");
    markers.forEach((marker, index) => {
        marker.firstElementChild.style.border = `1px solid ${
            color[index % color.length]
        }`;
    });
});

// 비행기 이동 애니메이션
const markers = document.querySelectorAll(".marker-circle.last");
let pos = -2;

setInterval(() => {
    pos += 1; // 1씩 증가
    if (pos > 97) {
        pos = -2;
        markers.forEach((marker) => {
            marker.style.transition = `left 0s linear`;
            marker.style.left = "-2%";
        });
    } else {
        markers.forEach((marker) => {
            marker.style.transition = `left 0.5s linear`;
            marker.style.left = pos + "%";
        });
    }
}, 100);

// 좋아요 클릭 이벤트
const likeBtns = document.querySelectorAll("button.card-item-action-btn.like");
const toast = document.querySelector("div.toast");
const toastText = document.querySelector("p.toast-text");
let likeDoubleClick = true; // 광클 방지
likeBtns.forEach((likeBtn) => {
    likeBtn.addEventListener("click", (e) => {
        if (!likeDoubleClick) return;
        likeDoubleClick = false;
        toast.style.display = "block";
        toast.classList.remove("hide");
        toast.classList.add("show");
        const svg = likeBtn.firstElementChild;
        if (svg.classList.contains("active")) {
            svg.classList.remove("active");
            toastText.textContent = "좋아요가 취소되었습니다.";
        } else {
            svg.classList.add("active");
            toastText.textContent = "좋아요가 추가되었습니다.";
        }
        setTimeout(() => {
            toast.classList.remove("show");
            toast.classList.add("hide");
            setTimeout(() => {
                likeDoubleClick = true;
                toast.style.display = "none";
            }, 1000);
        }, 2000);
    });
});

function startCountdown() {
    const timers = document.querySelectorAll("div.gift-limit-time");

    timers.forEach((timer) => {
        const endTime = new Date(timer.dataset.endtime);

        function updateTimer() {
            const now = new Date();
            const diff = endTime - now;

            if (diff <= 0) {
                timer.textContent = "마감";
                return;
            }

            const totalSeconds = Math.floor(diff / 1000);

            const days = Math.floor(totalSeconds / (3600 * 24));
            const hours = String(
                Math.floor((totalSeconds % (3600 * 24)) / 3600)
            ).padStart(2, "0");
            const minutes = String(
                Math.floor((totalSeconds % 3600) / 60)
            ).padStart(2, "0");
            const seconds = String(totalSeconds % 60).padStart(2, "0");

            if (days > 0) {
                timer.textContent = `${days}일 ${hours}:${minutes}:${seconds} 남음`;
            } else {
                timer.textContent = `${hours}:${minutes}:${seconds} 남음`;
            }
        }

        updateTimer();
        setInterval(updateTimer, 1000);
    });
}
